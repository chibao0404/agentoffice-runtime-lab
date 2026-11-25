import { spawn } from 'node:child_process';
import { constants, accessSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { networkInterfaces } from 'node:os';
import { performance } from 'node:perf_hooks';
import { createConnection } from 'node:net';

const source = new URL('.', import.meta.url);
const contract = JSON.parse(readFileSync(new URL('contract.json', source)));
const profile = '/home/node/lab';
const check = (condition) => {
  if (!condition) throw new Error('CONTRACT_VIOLATION');
};
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const fields = (value, required) => object(value) && required.every((key) => Object.hasOwn(value, key));
const remaining = (deadline) => Math.max(1, Math.floor(deadline - performance.now()));

function syntheticEgressCheck() {
  return new Promise((resolve, reject) => {
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

function absent(path) {
  try {
    accessSync(path, constants.F_OK);
  } catch (error) {
    check(error.code === 'ENOENT');
    return;
  }
  throw new Error('UNEXPECTED_PATH');
}

async function preflight() {
  check(process.platform === 'linux' && process.arch === 'x64');
  check(process.getuid() === 1000 && process.getgid() === 1000);
  const allowed = ['PATH', 'NODE_VERSION', 'YARN_VERSION', 'HOME', 'HOSTNAME', 'PWD'];
  check(Object.keys(process.env).every((name) => allowed.includes(name)));
  check(process.env.HOME === '/home/node');
  const status = readFileSync('/proc/self/status', 'utf8');
  check(/^CapEff:\s+0+$/m.test(status) && /^NoNewPrivs:\s+1$/m.test(status) && /^Seccomp:\s+2$/m.test(status));
  check(Object.keys(networkInterfaces()).join() === 'lo');
  check(readFileSync('/proc/net/route', 'utf8').trim().split('\n').length === 1);
  for (const path of ['/var/run/docker.sock', '/run/docker.sock', '/home/node/.codex', profile]) absent(path);
  try {
    writeFileSync('/app/readonly-canary', '', { flag: 'wx' });
    throw new Error('ROOT_WRITABLE');
  } catch (error) {
    check(error.code === 'EROFS' || error.code === 'EACCES');
  }
  await syntheticEgressCheck();
  for (const name of ['home', 'codex', 'config', 'data', 'cache', 'state', 'tmp']) {
    mkdirSync(profile + '/' + name, { recursive: true, mode: 0o700 });
  }
}

function createReader(child) {
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let bytes = 0;
  let pending = Buffer.alloc(0);
  let waiter;
  let failed = false;
  const reject = () => {
    failed = true;
    if (waiter) waiter.reject(new Error('PROTOCOL_BLOCKED'));
  };
  child.stdout.on('data', (chunk) => {
    bytes += chunk.length;
    if (failed || bytes > contract.totalBytes) return reject();
    pending = Buffer.concat([pending, chunk]);
    const last = pending.indexOf(10);
    if (last < 0 && pending.length <= contract.lineBytes) return;
    if (!waiter || last < 1 || last >= contract.lineBytes || last !== pending.length - 1) return reject();
    try {
      const value = JSON.parse(decoder.decode(pending.subarray(0, last)));
      const { id, resolve } = waiter;
      check(fields(value, ['id', 'result']) && value.id === id &&
        Object.keys(value).every((key) => ['id', 'result', 'jsonrpc'].includes(key)) &&
        (value.jsonrpc === undefined || value.jsonrpc === '2.0'));
      waiter = undefined;
      pending = Buffer.alloc(0);
      resolve(value.result);
    } catch {
      reject();
    }
  });
  let stderrBytes = 0;
  child.stderr.on('data', (chunk) => {
    stderrBytes += chunk.length;
    if (stderrBytes > contract.totalBytes) reject();
  });
  child.on('error', reject);
  child.stdin.on('error', reject);
  child.on('close', () => { if (waiter || pending.length) reject(); });
  return {
    isValid: () => !failed,
    request(message, deadline) {
      check(!failed && !waiter);
      return new Promise((resolve, rejectRequest) => {
        const timer = setTimeout(reject, remaining(deadline));
        waiter = {
          id: message.id,
          resolve(value) { clearTimeout(timer); resolve(value); },
          reject(error) { clearTimeout(timer); rejectRequest(error); },
        };
        child.stdin.write(JSON.stringify(message) + '\n');
      });
    },
  };
}

const waitUntil = (closed, ms) => new Promise((resolve) => {
  const timer = setTimeout(() => resolve(null), ms);
  closed.then((result) => { clearTimeout(timer); resolve(result); });
});

function validateSnapshot(result, definitions) {
  check(fields(result, definitions.v2.ConfigReadResponse.required));
  check(object(result.config) && object(result.origins) && result.layers == null);
  check(!Object.hasOwn(result.config, 'mcp_servers') ||
    result.config.mcp_servers == null ||
    (object(result.config.mcp_servers) && Object.keys(result.config.mcp_servers).length === 0));
  for (const origin of Object.values(result.origins)) {
    check(object(origin) && object(origin.name) && origin.name.type === 'user' &&
      origin.name.file === profile + '/codex/config.toml');
  }
}

async function run() {
  check(JSON.stringify(contract.methods) === '["initialize","initialized","config/read"]');
  check(contract.runMs === 15000 && contract.shutdownMs === 5000);
  await preflight();
  const { definitions } = JSON.parse(readFileSync(new URL('schema.json', source)));
  const launchAt = performance.now();
  const child = spawn('/app/codex', ['app-server', '--listen', 'stdio://'], {
    cwd: profile + '/tmp',
    env: {
      PATH: '/usr/bin:/bin', HOME: profile + '/home', CODEX_HOME: profile + '/codex',
      XDG_CONFIG_HOME: profile + '/config', XDG_DATA_HOME: profile + '/data',
      XDG_CACHE_HOME: profile + '/cache', XDG_STATE_HOME: profile + '/state', TMPDIR: profile + '/tmp',
    },
    shell: false, stdio: ['pipe', 'pipe', 'pipe'],
  });
  const closed = new Promise((resolve) => {
    child.once('close', (code, signal) => resolve({ code, signal }));
  });
  const reader = createReader(child);
  const deadline = launchAt + contract.runMs;
  let protocolPassed = false;
  try {
    const init = await reader.request({
      id: 1, method: 'initialize', params: { clientInfo: { name: 'synthetic_probe', version: '1.0.0' } },
    }, deadline);
    check(fields(init, definitions.InitializeResponse.required));
    check(init.platformFamily === 'unix' && init.platformOs === 'linux' &&
      init.codexHome === profile + '/codex' && typeof init.userAgent === 'string');
    child.stdin.write('{"method":"initialized"}\n');
    const result = await reader.request({
      id: 2, method: 'config/read', params: { includeLayers: false },
    }, deadline);
    validateSnapshot(result, definitions);
    protocolPassed = reader.isValid() && performance.now() <= deadline;
  } finally {
    const shutdownAt = performance.now();
    const shutdownDeadline = shutdownAt + contract.shutdownMs;
    child.stdin.end();
    let exit = await waitUntil(closed, Math.min(3000, remaining(shutdownDeadline)));
    if (exit === null) {
      child.kill('SIGTERM');
      exit = await waitUntil(closed, Math.min(1000, remaining(shutdownDeadline)));
    }
    if (exit === null) {
      child.kill('SIGKILL');
      exit = await waitUntil(closed, remaining(shutdownDeadline));
    }
    const shutdownMs = Math.ceil(performance.now() - shutdownAt);
    const runMs = Math.ceil(shutdownAt - launchAt);
    check(protocolPassed && reader.isValid() && exit?.code === 0 && exit.signal === null &&
      runMs <= contract.runMs && shutdownMs <= contract.shutdownMs);
    console.log(JSON.stringify({ status: 'PASS_PROTOCOL_LINUX', preflight: true, childReaped: true, runMs, shutdownMs }));
  }
}

run().catch(() => {
  console.log('BLOCKED_PROTOCOL_OR_ISOLATION');
  process.exitCode = 1;
});
