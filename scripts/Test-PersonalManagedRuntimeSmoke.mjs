import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { mkdir, lstat } from 'node:fs/promises'
import { createServer as createHttpServer } from 'node:http'
import { createServer } from 'node:net'
import { isAbsolute, join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const protocol = 'ensou.dsh.runtime-update.v1'
const receiptKeys = ['activeOperations', 'operationId', 'persistenceFlushed', 'phase', 'processId', 'protocol', 'runtimeInstanceId']

// A smoke receipt must come from the child that this test actually launched.
export function validateReceipt(text, identity, operationId) {
  if (Buffer.byteLength(text) > 8192) throw new Error('receipt-size')
  const value = JSON.parse(text)
  assert.deepEqual(Object.keys(value).sort(), receiptKeys)
  assert.equal(JSON.stringify(value), text)
  assert.equal(value.protocol, protocol)
  assert.equal(value.runtimeInstanceId, identity.instance)
  assert.equal(value.processId, identity.pid)
  assert.equal(value.operationId, operationId)
  assert.ok(['draining', 'ready', 'resumed'].includes(value.phase))
  assert.ok(Number.isSafeInteger(value.activeOperations) && value.activeOperations >= 0)
  assert.equal(typeof value.persistenceFlushed, 'boolean')
  if (value.phase === 'ready') {
    assert.equal(value.activeOperations, 0)
    assert.equal(value.persistenceFlushed, true)
  }
  return value
}

async function listen(server, endpoint) {
  await new Promise((accept, reject) => {
    server.once('error', reject)
    server.listen(endpoint, () => { server.removeListener('error', reject); accept() })
  })
}

async function reservePort() {
  const server = createServer()
  await listen(server, { host: '127.0.0.1', port: 0 })
  const port = server.address().port
  await new Promise((accept, reject) => server.close(error => error ? reject(error) : accept()))
  return port
}

async function within(operation, milliseconds, code) {
  let timer
  try {
    return await Promise.race([operation, new Promise((_accept, reject) => {
      timer = setTimeout(() => reject(new Error(code)), milliseconds)
    })])
  } finally { clearTimeout(timer) }
}

async function closeServer(server) {
  if (!server.listening) return
  await within(new Promise((accept, reject) => server.close(error => error ? reject(error) : accept())),
    5000, 'test-server-cleanup-timeout')
}

export async function runSmoke(runtime, smokeRoot) {
  assert.equal(process.platform, 'win32')
  assert.ok(isAbsolute(runtime) && isAbsolute(smokeRoot))
  runtime = resolve(runtime)
  smokeRoot = resolve(smokeRoot)
  for (const path of [runtime, join(runtime, 'node.exe'), join(runtime, 'node_modules', '@deepseek-ai', 'dsh', 'lib', 'bin.js')]) {
    const info = await lstat(path)
    assert.equal(info.isSymbolicLink(), false)
  }
  await mkdir(smokeRoot) // create-only; never adopt an existing home
  const workspace = join(smokeRoot, 'workspace')
  await mkdir(workspace)
  const instance = randomUUID()
  const pipeName = `\\\\.\\pipe\\ensou-dsh-update-${instance.replaceAll('-', '')}`
  const pipe = createServer()
  const api = createHttpServer((_request, response) => {
    response.writeHead(503, { 'content-type': 'application/json', connection: 'close' })
    response.end('{"error":{"message":"No external API in runtime smoke"}}')
  })
  let child
  let socket
  let pending = Buffer.alloc(0)
  let responseWaiter
  let connectResolve
  let shutdownExpected = false
  let fail
  const fatal = new Promise((_resolve, reject) => { fail = reject })
  void fatal.catch(() => {})
  const connected = new Promise(accept => { connectResolve = accept })
  const deadline = setTimeout(() => fail(new Error('personal-smoke-deadline')), 180_000)
  const bounded = operation => Promise.race([operation, fatal])
  pipe.on('error', fail)
  api.on('error', fail)
  pipe.on('connection', incoming => {
    if (socket) { incoming.destroy(); fail(new Error('duplicate-update-client')); return }
    socket = incoming
    incoming.on('error', fail)
    incoming.on('close', () => {
      if (!shutdownExpected || responseWaiter) fail(new Error('update-channel-closed'))
    })
    incoming.on('data', bytes => {
      if (!responseWaiter) { fail(new Error('unsolicited-update-response')); return }
      pending = Buffer.concat([pending, bytes])
      if (pending.length > 8192) { fail(new Error('unbounded-update-response')); return }
      const newline = pending.indexOf(10)
      if (newline < 0) return
      if (newline !== pending.length - 1 || !responseWaiter) { fail(new Error('unsolicited-update-response')); return }
      const accept = responseWaiter
      responseWaiter = undefined
      try {
        const text = new TextDecoder('utf-8', { fatal: true }).decode(pending.subarray(0, newline))
        pending = Buffer.alloc(0)
        accept(text)
      } catch (error) { fail(error) }
    })
    connectResolve()
  })
  try {
    await bounded(listen(pipe, pipeName))
    await bounded(listen(api, { host: '127.0.0.1', port: 0 }))
    const webPort = await bounded(reservePort())
    const environment = {}
    for (const key of ['SystemRoot', 'WINDIR', 'ComSpec', 'SystemDrive', 'ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432']) {
      const entry = Object.entries(process.env).find(([name]) => name.toLowerCase() === key.toLowerCase())
      if (entry) environment[key] = entry[1]
    }
    for (const key of ['USERPROFILE', 'HOME', 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP']) {
      environment[key] = join(smokeRoot, key)
      await mkdir(environment[key])
    }
    Object.assign(environment, {
      PATH: `${runtime};${join(environment.SystemRoot, 'System32')}`,
      DSH_HOME: join(smokeRoot, '.dsh'), DSH_AGENTS_HOME: join(smokeRoot, '.agents'),
      DSH_TELEMETRY_DISABLED: '1', NO_PROXY: '127.0.0.1,localhost',
      DEEPSEEK_API_KEY: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      DEEPSEEK_BASE_URL: `http://127.0.0.1:${api.address().port}/v1`,
      DEEPSEEK_SEARCH_BASE_URL: `http://127.0.0.1:${api.address().port}/v1`,
      ENSOU_DSH_PERSONAL_UPDATE_BOOT: 'ensou-dsh-personal-launcher/v1',
      ENSOU_DSH_UPDATE_PIPE: pipeName, ENSOU_DSH_RUNTIME_INSTANCE_ID: instance,
    })
    child = spawn(join(runtime, 'node.exe'), [
      join(runtime, 'node_modules', '@deepseek-ai', 'dsh', 'lib', 'bin.js'),
      '--profile', 'web', '--no-open', '--host', '127.0.0.1', '--port', String(webPort),
    ], { cwd: workspace, env: environment, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] })
    child.once('error', fail)
    let outputBytes = 0
    for (const stream of [child.stdout, child.stderr]) {
      stream.on('error', fail)
      stream.on('data', data => {
        outputBytes += data.length
        if (outputBytes > 8 * 1024 * 1024) fail(new Error('runtime-log-limit'))
      })
    }
    const exited = new Promise(accept => child.once('exit', (code, signal) => accept({ code, signal })))
    await bounded(Promise.race([connected, exited.then(() => { throw new Error('runtime-exited-before-connect') })]))
    const anonymous = await bounded(fetch(`http://127.0.0.1:${webPort}/`, {
      redirect: 'manual', headers: { connection: 'close' }, signal: AbortSignal.timeout(5000),
    }))
    await anonymous.body?.cancel()
    assert.equal(anonymous.status, 401)
    const identity = { instance, pid: child.pid }
    const request = async (action, operationId) => {
      assert.equal(responseWaiter, undefined)
      const response = new Promise(accept => { responseWaiter = accept })
      socket.write(`${JSON.stringify({ protocol, runtimeInstanceId: instance, operationId, action })}\n`)
      try {
        return validateReceipt(await bounded(within(response, 15000, 'update-response-timeout')), identity, operationId)
      } finally { responseWaiter = undefined }
    }
    const drain = async operationId => {
      let receipt = await request('drain', operationId)
      while (receipt.phase === 'draining') {
        await bounded(new Promise(accept => setTimeout(accept, 50)))
        receipt = await request('status', operationId)
      }
      assert.equal(receipt.phase, 'ready')
      return receipt
    }
    const first = randomUUID()
    await drain(first)
    assert.equal((await request('resume', first)).phase, 'resumed')
    const second = randomUUID()
    await drain(second)
    shutdownExpected = true
    assert.equal((await request('shutdown', second)).phase, 'ready')
    const exit = await bounded(exited)
    assert.deepEqual(exit, { code: 0, signal: null })
    return { status: 'PASS', scope: 'BUILT_PERSONAL_PROFILE_IDLE_UPDATE_PROTOCOL_ONLY', cycles: 2, anonymousRootRejected: true, exactChildExited: true, outputBytes }
  } finally {
    clearTimeout(deadline)
    socket?.destroy()
    api.closeAllConnections()
    const serverCleanup = Promise.all([closeServer(api), closeServer(pipe)])
    void serverCleanup.catch(() => {})
    if (child && child.exitCode === null && child.signalCode === null) {
      child.kill() // only the synthetic child created above; no process-name sweep
      await within(new Promise(accept => child.once('exit', accept)), 5000, 'synthetic-child-cleanup-timeout')
    }
    await serverCleanup
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const [runtime, smokeRoot] = process.argv.slice(2)
    console.log(JSON.stringify(await runSmoke(runtime, smokeRoot)))
  } catch (error) {
    console.error(JSON.stringify({ status: 'FAIL', failureType: error?.constructor?.name ?? 'Error' }))
    process.exitCode = 1
  }
}
