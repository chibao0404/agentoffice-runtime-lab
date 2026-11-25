import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { accessSync, chmodSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { createConnection } from 'node:net';
import { networkInterfaces } from 'node:os';
import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';

const source = new URL('.', import.meta.url);
const contract = JSON.parse(readFileSync(new URL('contract.json', source)));
const profile = '/home/node/lab';
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const own = (value, keys) => object(value) && keys.every((key) => Object.hasOwn(value, key));
const positiveInt = (v) => Number.isSafeInteger(v) && v > 0;

function need(condition, code = 'CONTRACT_VIOLATION') {
  if (!condition) throw new Error(code);
}

function errno(action, expected) {
  try { action(); } catch (error) { need(error.code === expected, 'FILESYSTEM_UNVERIFIED'); return; }
  throw new Error('FILESYSTEM_UNVERIFIED');
}

function preflightFiles() {
  const entries = readFileSync('/proc/self/mountinfo', 'utf8').trim().split('\n')
    .map((line) => line.split(' - ')[0].split(' '));
  const mount = (name) => entries.find((fields) => fields[4] === name)?.[5]?.split(',') ?? [];
  need(mount('/').includes('ro') && mount('/tmp').includes('rw') && mount('/home/node').includes('rw'));
  // Docker-managed hosts, hostname and resolv.conf may be injected. Reject extra mounts outside kernel paths.
  const named = new Set(['/', '/tmp', '/home/node', '/etc/hosts', '/etc/hostname', '/etc/resolv.conf']);
  need(entries.every(([, , , , target]) => named.has(target) || /^\/(proc|sys|dev)(\/|$)/.test(target)));
  const missing = ['/var/run/docker.sock', '/run/docker.sock', '/run/secrets', '/root/.codex', '/home/node/.codex',
    '/home/node/.ssh', '/home/node/.config', '/home/node/.aws', '/github/workspace', '/workspace', '/mnt/c', profile];
  // /root is itself inaccessible to UID 1000; inspect standard credential paths only under accessible mounts.
  for (const path of missing.filter((path) => path !== '/root/.codex')) errno(() => accessSync(path), 'ENOENT');
  mkdirSync(profile, { mode: 0o700 });
  for (const name of ['home', 'codex', 'config', 'data', 'cache', 'state', 'tmp']) {
    mkdirSync(profile + '/' + name, { mode: 0o700 });
  }
  const canary = profile + '/tmp/canary';
  writeFileSync(canary, 'synthetic', { flag: 'wx' });
  need(readFileSync(canary, 'utf8') === 'synthetic');
  chmodSync(canary, 0o400);
  errno(() => writeFileSync(canary, 'wrong'), 'EACCES');
  unlinkSync(canary);
  // Image build creates a 0666 canary. EROFS, not DAC, must be the cause here.
  errno(() => writeFileSync('/app/readonly-canary', 'wrong'), 'EROFS');
}

async function preflight() {
  need(process.platform === 'linux' && process.arch === 'x64' && process.getuid() === 1000 && process.getgid() === 1000);
  const allowed = ['PATH', 'NODE_VERSION', 'YARN_VERSION', 'HOME', 'HOSTNAME', 'PWD'];
  need(Object.keys(process.env).every((name) => allowed.includes(name)) && process.env.HOME === '/home/node');
  const status = readFileSync('/proc/self/status', 'utf8');
  need(/^CapEff:\s+0+$/m.test(status) && /^NoNewPrivs:\s+1$/m.test(status) && /^Seccomp:\s+2$/m.test(status));
  need(Object.keys(networkInterfaces()).join() === 'lo');
  need(readFileSync('/proc/net/route', 'utf8').trim().split('\n').length === 1);
  preflightFiles();
  await new Promise((resolve, reject) => {
    const socket = createConnection({ host: '192.0.2.1', port: 9 });
    socket.setTimeout(250);
    socket.once('error', (error) => {
      socket.destroy();
      if (['ENETUNREACH', 'EHOSTUNREACH'].includes(error.code)) resolve();
      else reject(new Error('NETWORK_UNVERIFIED'));
    });
    for (const event of ['timeout', 'connect']) {
      socket.once(event, () => {
        socket.destroy();
        reject(new Error('NETWORK_UNVERIFIED'));
      });
    }
  });
}

export function loadPinnedSchema(bytes) {
  need(createHash('sha256').update(bytes).digest('hex') === contract.schemaSha256);
  const { definitions } = JSON.parse(bytes);
  const expected = contract.projected;
  need(JSON.stringify([...definitions.InitializeResponse.required].sort()) === JSON.stringify(expected.initializeRequired));
  need(JSON.stringify([...definitions.v2.ConfigReadResponse.required].sort()) === JSON.stringify(expected.configRequired));
  need(JSON.stringify(definitions.v2.SandboxMode.enum) === JSON.stringify(expected.sandboxModes));
  need(JSON.stringify(definitions.v2.AskForApproval.oneOf[0].enum) === JSON.stringify(expected.approvalPolicies));
  return definitions;
}

function validateInit(result) {
  need(own(result, contract.projected.initializeRequired));
  need(result.platformFamily === 'unix' && result.platformOs === 'linux' &&
    result.codexHome === profile + '/codex' && typeof result.userAgent === 'string' && result.userAgent.length > 0);
}

function validateConfig(result) {
  need(own(result, contract.projected.configRequired) && object(result.config) && object(result.origins));
  need(result.layers === undefined || result.layers === null);
  const c = result.config;
  for (const key of ['model', 'model_provider']) {
    need(!Object.hasOwn(c, key) || c[key] === null || typeof c[key] === 'string');
  }
  need(c.sandbox_mode == null || contract.projected.sandboxModes.includes(c.sandbox_mode));
  const a = c.approval_policy;
  const flags = ['mcp_elicitations', 'rules', 'sandbox_approval', 'request_permissions', 'skill_approval'];
  const granular = own(a, ['granular']) && Object.keys(a).length === 1 && own(a.granular, flags.slice(0, 3)) &&
    Object.entries(a.granular).every(([key, value]) => flags.includes(key) && typeof value === 'boolean');
  need(a == null || contract.projected.approvalPolicies.includes(a) || granular);
  need(c.mcp_servers == null || (object(c.mcp_servers) && Object.keys(c.mcp_servers).length === 0));
  for (const origin of Object.values(result.origins)) {
    need(own(origin, ['name', 'version']) && typeof origin.version === 'string' && own(origin.name, ['type', 'file']));
    need(origin.name.type === 'user' && origin.name.file === profile + '/codex/config.toml');
    need(origin.name.profile == null);
  }
}

function makeReader(child) {
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let pending = Buffer.alloc(0), total = 0, stderrBytes = 0, waiter, failure;
  function reject(code) {
    failure ??= code;
    if (waiter) waiter.reject(new Error(failure));
  }
  child.stdout.on('data', (bytes) => {
    total += bytes.length;
    if (total > contract.totalBytes) return reject('OVERSIZED_OUTPUT');
    if (failure) return;
    if (!waiter) return reject('UNEXPECTED_RPC');
    pending = Buffer.concat([pending, bytes]);
    const end = pending.indexOf(10);
    if (pending.length > contract.lineBytes) return reject('OVERSIZED_OUTPUT');
    if (end < 0) return;
    if (end < 1 || end !== pending.length - 1) return reject('UNEXPECTED_RPC');
    let response;
    try { response = JSON.parse(decoder.decode(pending.subarray(0, end))); }
    catch { return reject('MALFORMED_RESPONSE'); }
    if (!own(response, ['id', 'result']) ||
      Object.keys(response).some((key) => !['id', 'result', 'jsonrpc'].includes(key)) ||
      (response.jsonrpc !== undefined && response.jsonrpc !== '2.0')) return reject('UNEXPECTED_RPC');
    if (response.id !== waiter.id) return reject('CORRELATION_MISMATCH');
    const resolve = waiter.resolve;
    waiter = undefined;
    pending = Buffer.alloc(0);
    resolve(response.result);
  });
  child.stderr.on('data', (bytes) => {
    stderrBytes += bytes.length;
    if (stderrBytes > contract.totalBytes) reject('OVERSIZED_OUTPUT');
  });
  child.stdin.on('error', () => reject('STDIO_FAILED'));
  child.on('error', () => reject('SPAWN_FAILED'));
  child.on('close', () => { if (waiter || pending.length) reject('EARLY_EXIT'); });
  function send(message) {
    if (failure) throw new Error(failure);
    child.stdin.write(JSON.stringify(message) + '\n');
  }
  return {
    failure: () => failure,
    send,
    request(message, deadline) {
      const delay = Math.max(0, Math.floor(deadline - performance.now()));
      return new Promise((resolve, fail) => {
        if (failure || waiter || delay === 0) return fail(new Error(failure ?? 'EXECUTION_TIMEOUT'));
        const timer = setTimeout(() => reject('EXECUTION_TIMEOUT'), delay);
        waiter = {
          id: message.id,
          resolve(value) { clearTimeout(timer); resolve(value); },
          reject(error) { clearTimeout(timer); waiter = undefined; fail(error); },
        };
        send(message);
      });
    },
  };
}

function aliveGroup(child, grouped) {
  if (!grouped || !positiveInt(child.pid)) return false;
  try { process.kill(-child.pid, 0); return true; }
  catch (error) { if (error.code === 'ESRCH') return false; throw error; }
}

function signal(child, grouped, name) {
  try {
    if (grouped && positiveInt(child.pid)) process.kill(-child.pid, name);
    else if (child.exitCode === null && child.signalCode === null) child.kill(name);
  } catch (error) {
    if (error.code !== 'ESRCH') throw error;
  }
}

async function awaitStopped(child, exitStatus, grouped, until) {
  while (performance.now() < until) {
    if (exitStatus() !== null && !aliveGroup(child, grouped)) return true;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  return exitStatus() !== null && !aliveGroup(child, grouped);
}

const codes = new Set(['CONTRACT_VIOLATION', 'OVERSIZED_OUTPUT', 'UNEXPECTED_RPC', 'MALFORMED_RESPONSE',
  'CORRELATION_MISMATCH', 'STDIO_FAILED', 'SPAWN_FAILED', 'EARLY_EXIT', 'EXECUTION_TIMEOUT']);

export async function supervise(executable, args, options, bounds) {
  const launchAt = performance.now();
  const grouped = process.platform === 'linux';
  const child = spawn(executable, args, { ...options, detached: grouped, shell: false, stdio: ['pipe', 'pipe', 'pipe'] });
  let exit = null;
  child.once('close', (code, sig) => { exit = { code, sig }; });
  const reader = makeReader(child);
  const executionDeadline = launchAt + bounds.runMs;
  let code = 'PROTOCOL_COMPLETE';
  try {
    const init = await reader.request({
      id: 1, method: 'initialize', params: { clientInfo: { name: 'synthetic_probe', version: '1.1.0' } },
    }, executionDeadline);
    validateInit(init);
    reader.send({ method: 'initialized' });
    validateConfig(await reader.request({ id: 2, method: 'config/read', params: { includeLayers: false } }, executionDeadline));
    need(performance.now() <= executionDeadline, 'EXECUTION_TIMEOUT');
  } catch (error) {
    code = codes.has(error.message) ? error.message : 'CONTRACT_VIOLATION';
  }
  const shutdownAt = performance.now();
  const shutdownDeadline = shutdownAt + bounds.shutdownMs;
  const graceDeadline = shutdownAt + bounds.graceMs;
  const termDeadline = shutdownAt + bounds.termMs;
  child.stdin.end();
  let action = 'EOF';
  const stopped = (until) => awaitStopped(child, () => exit, grouped, until);
  let confirmed = await stopped(graceDeadline);
  if (!confirmed) {
    action = 'TERM';
    signal(child, grouped, 'SIGTERM');
    confirmed = await stopped(termDeadline);
  }
  if (!confirmed) {
    action = 'KILL';
    signal(child, grouped, 'SIGKILL');
    confirmed = await stopped(shutdownDeadline);
  }
  const runMs = Math.ceil(shutdownAt - launchAt);
  const shutdownMs = Math.ceil(performance.now() - shutdownAt);
  const childReaped = exit !== null;
  const teardownConfirmed = confirmed && childReaped && shutdownMs <= bounds.shutdownMs;
  const reason = !teardownConfirmed ? 'TEARDOWN_UNVERIFIED'
    : reader.failure() ?? (code !== 'PROTOCOL_COMPLETE' ? code
      : action !== 'EOF' ? 'FORCED_SHUTDOWN' : exit.code !== 0 || exit.sig ? 'ABNORMAL_EXIT'
        : runMs > bounds.runMs ? 'EXECUTION_TIMEOUT' : 'OK');
  return { reason, childReaped, teardownConfirmed, action, runMs, shutdownMs };
}

const childSource = String.raw`
const mode=process.argv[1];
if(mode==='ignore'||mode==='descendant'){
  process.on('SIGTERM',()=>{});
  setInterval(()=>{},1000);
}
if(mode==='descendant'){
  require('node:child_process').spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});
}
if(mode==='timeout'||mode==='ignore'||mode==='descendant'){
  process.stdin.resume();
  if(mode==='timeout')process.stdin.on('end',()=>process.exit(0));
}else{
 const readline=require('node:readline').createInterface({input:process.stdin});
 readline.on('line',line=>{
  const p=JSON.parse(line);
  if(p.method==='initialized')return;
  if(p.method==='initialize'){
    const result={platformFamily:'unix',platformOs:'linux',codexHome:'/home/node/lab/codex',userAgent:'synthetic'};
    if(mode==='missing')delete result.userAgent;
    if(mode==='wrongtype')result.userAgent=42;
    if(mode==='rpc')return console.log('{"method":"unexpected","id":8}');
    if(mode==='malformed')return console.log('{');
    if(mode==='oversized')return console.log('x'.repeat(70000));
    return console.log(JSON.stringify({id:mode==='wrongid'?99:p.id,result}));
  }
  const result={config:{sandbox_mode:'read-only',approval_policy:'never'},origins:{},layers:null};
  if(mode==='bad-enum')result.config.sandbox_mode='unknown';
  if(mode==='bad-structure')result.origins={a:{name:{type:'user'},version:42}};
  if(mode==='bad-layers')result.layers=[];
  console.log(JSON.stringify({id:p.id,result}));
  if(mode==='abnormal')readline.once('close',()=>process.exit(9));
 });
}
`;

export async function syntheticSuite({ requireLinux = false } = {}) {
  if (requireLinux) need(process.platform === 'linux');
  const cases = [
    ['normal', 'OK'], ['missing', 'CONTRACT_VIOLATION'], ['wrongtype', 'CONTRACT_VIOLATION'],
    ['bad-enum', 'CONTRACT_VIOLATION'], ['bad-structure', 'CONTRACT_VIOLATION'],
    ['bad-layers', 'CONTRACT_VIOLATION'], ['malformed', 'MALFORMED_RESPONSE'],
    ['rpc', 'UNEXPECTED_RPC'], ['wrongid', 'CORRELATION_MISMATCH'],
    ['oversized', 'OVERSIZED_OUTPUT'], ['timeout', 'EXECUTION_TIMEOUT'], ['abnormal', 'ABNORMAL_EXIT'],
  ];
  if (process.platform === 'linux') cases.push(['ignore', 'EXECUTION_TIMEOUT'], ['descendant', 'EXECUTION_TIMEOUT']);
  const results = [];
  for (const [name, expected] of cases) {
    const bounds = { runMs: ['ignore', 'descendant', 'timeout'].includes(name) ? 300 : 1000,
      graceMs: 150, termMs: 350, shutdownMs: 1500 };
    const result = await supervise(process.execPath, ['-e', childSource, name], { env: {} }, bounds);
    need(result.reason === expected && result.childReaped && result.teardownConfirmed, 'SYNTHETIC_CASE_FAILED_' + name);
    if (name === 'ignore' || name === 'descendant') need(result.action === 'KILL', 'SYNTHETIC_FORCE_KILL_MISSING');
    results.push({ name, reason: result.reason, action: result.action, teardownConfirmed: result.teardownConfirmed });
  }
  return results;
}

async function main() {
  need(JSON.stringify(contract.methods) === '["initialize","initialized","config/read"]');
  need(JSON.stringify(contract.bounds) === '{"runMs":15000,"graceMs":3000,"termMs":4000,"shutdownMs":5000}');
  await preflight();
  loadPinnedSchema(readFileSync(new URL('schema.json', source)));
  if (process.argv.length === 3 && process.argv[2] === '--synthetic-verify') {
    const cases = await syntheticSuite({ requireLinux: true });
    console.log(JSON.stringify({ status: 'PASS_SYNTHETIC_PROFILE', preflight: true, cases: cases.length,
      allStopped: cases.every((item) => item.teardownConfirmed) }));
    return;
  }
  need(process.argv.length === 2);
  const env = {
    PATH: '/usr/bin:/bin', HOME: profile + '/home', CODEX_HOME: profile + '/codex',
    XDG_CONFIG_HOME: profile + '/config', XDG_DATA_HOME: profile + '/data',
    XDG_CACHE_HOME: profile + '/cache', XDG_STATE_HOME: profile + '/state', TMPDIR: profile + '/tmp',
  };
  const r = await supervise('/app/codex', ['app-server', '--listen', 'stdio://'], { cwd: profile + '/tmp', env }, contract.bounds);
  need(r.reason === 'OK' && r.teardownConfirmed);
  console.log(JSON.stringify({ status: 'PASS_PROTOCOL_LINUX', preflight: true, childReaped: r.childReaped,
    runMs: r.runMs, shutdownMs: r.shutdownMs }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => { console.log('BLOCKED_PROTOCOL_OR_ISOLATION'); process.exitCode = 1; });
}
