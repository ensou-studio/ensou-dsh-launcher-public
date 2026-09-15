import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { lstat, mkdir, realpath } from 'node:fs/promises'
import { createServer } from 'node:net'
import { isAbsolute, join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { createContext, Script } from 'node:vm'
import { validateReceipt } from './Test-PersonalManagedRuntimeSmoke.mjs'

export { validateReceipt }

const updateProtocol = 'ensou.dsh.runtime-update.v1'
const managedBootMarker = 'ensou-dsh-launcher/v1'
const clientModulesId = '@deepseek-ai/dsh-client-modules'
const maximumBodyBytes = 1024 * 1024
const diagnosticStages = new Set([
  'runtime-layout',
  'smoke-root',
  'update-pipe-listen',
  'launch-refusals',
  'runtime-spawn',
  'runtime-readiness-url',
  'update-pipe-connect',
  'launch-url-contract',
  'anonymous-auth',
  'token-exchange',
  'forged-auth',
  'authenticated-root',
  'kernel-bootstrap',
  'settings-capability',
  'credential-cycle',
  'update-cycle-1-drain',
  'update-cycle-1-resume',
  'update-cycle-2-drain',
  'update-cycle-2-shutdown',
  'runtime-exit',
])

export function createFailureReceipt(stage, _error) {
  return {
    status: 'FAIL',
    resultStatus: 'FAIL',
    failureType: 'Error',
    failureStage: diagnosticStages.has(stage) ? stage : 'unclassified',
  }
}

async function listen(server, endpoint) {
  await new Promise((accept, reject) => {
    server.once('error', reject)
    server.listen(endpoint, () => {
      server.removeListener('error', reject)
      accept()
    })
  })
}

async function reservePort() {
  const server = createServer()
  await listen(server, { host: '127.0.0.1', port: 0 })
  const address = server.address()
  if (address === null || typeof address === 'string') throw new Error('loopback-port-reservation')
  const port = address.port
  await new Promise((accept, reject) => server.close(error => error ? reject(error) : accept()))
  return port
}

async function within(operation, milliseconds, code) {
  let timer
  try {
    return await Promise.race([
      operation,
      new Promise((_accept, reject) => {
        timer = setTimeout(() => reject(new Error(code)), milliseconds)
      }),
    ])
  } finally {
    clearTimeout(timer)
  }
}

async function closeServer(server) {
  if (!server.listening) return
  await within(
    new Promise((accept, reject) => server.close(error => error ? reject(error) : accept())),
    5000,
    'test-server-cleanup-timeout',
  )
}

function decodeCanonicalBase64Url(value, maximumBytes) {
  if (typeof value !== 'string' || value.length === 0 || value.length > maximumBytes * 2
      || value.length % 4 === 1 || !/^[A-Za-z0-9_-]+$/.test(value)) return undefined
  const decoded = Buffer.from(value, 'base64url')
  return decoded.length <= maximumBytes && decoded.toString('base64url') === value
    ? decoded
    : undefined
}

function validateBrowserSetCookie(setCookie, authority) {
  const segments = setCookie.split(';')
  const maxAge = segments[1]?.slice(' Max-Age='.length)
  const expires = segments[3]?.slice(' Expires='.length)
  if (segments.length !== 6 || !segments[1]?.startsWith(' Max-Age=')
      || !/^[1-9][0-9]*$/.test(maxAge) || !Number.isSafeInteger(Number(maxAge))
      || segments[2] !== ' Path=/' || !segments[3]?.startsWith(' Expires=')
      || Number.isNaN(Date.parse(expires)) || segments[4] !== ' HttpOnly'
      || segments[5] !== ' SameSite=Strict') {
    throw new Error('browser-cookie-contract')
  }
  const separator = segments[0].indexOf('=')
  const expectedName = 'dsh-auth-' + createHash('sha256').update(authority).digest('base64url')
  const name = segments[0].slice(0, separator)
  const value = segments[0].slice(separator + 1)
  const parts = value.split('.')
  if (separator <= 0 || name !== expectedName || parts.length !== 3 || parts[0] !== 'v1'
      || decodeCanonicalBase64Url(parts[1], 2048) === undefined
      || parts[2].length !== 43 || decodeCanonicalBase64Url(parts[2], 32)?.length !== 32) {
    throw new Error('browser-cookie-shape')
  }
  return segments[0]
}

async function readBoundedText(response, label) {
  const declared = response.headers.get('content-length')
  if (declared !== null
      && (!/^[0-9]+$/.test(declared) || Number(declared) > maximumBodyBytes)) {
    throw new Error(label + '-declared-size')
  }
  if (response.body === null) return ''
  const reader = response.body.getReader()
  const chunks = []
  let total = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > maximumBodyBytes) {
        await reader.cancel()
        throw new Error(label + '-body-size')
      }
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, total))
  } catch {
    throw new Error(label + '-utf8')
  }
}

function exactClientModulesUrl(revision, allowInitialRevision = false) {
  if (typeof revision !== 'string' || revision.length > 33) return undefined
  // The pinned runtime gives individual initial rows an opaque nonce-counter
  // revision; a bootstrap batch always uses a twelve-hex artifact hash.
  const initial = allowInitialRevision
    ? /^([0-9a-f]{16})-(0|[1-9][0-9]{0,15})$/.exec(revision)
    : null
  if (!/^[0-9a-f]{12}$/.test(revision)
      && (initial === null || !Number.isSafeInteger(Number(initial[2])))) return undefined
  return `/plugins/??${clientModulesId}/client.js&rev=${revision}`
}

function parseBootGraph(html) {
  const marker = 'globalThis["__DSH_BOOT__"] = '
  const start = html.indexOf(marker)
  if (start < 0) throw new Error('enterprise-boot-graph-missing')
  const end = html.indexOf('</script>', start + marker.length)
  if (end < 0) throw new Error('enterprise-boot-graph-unbounded')
  let source = html.slice(start + marker.length, end).trim()
  if (source.endsWith(';')) source = source.slice(0, -1)
  let graph
  try {
    graph = JSON.parse(source)
  } catch {
    throw new Error('enterprise-boot-graph-invalid')
  }
  if (graph === null || typeof graph !== 'object' || Array.isArray(graph)
      || !Array.isArray(graph.entries) || !Array.isArray(graph.batches)) {
    throw new Error('enterprise-boot-graph-shape')
  }
  return graph
}

// The inline queue is the client-module kernel. A graph alone is insufficient:
// without this queue the bootstrap bundle cannot materialize the Web client.
export function validateEnterpriseBootHtml(html) {
  if (typeof html !== 'string' || Buffer.byteLength(html, 'utf8') > maximumBodyBytes) {
    throw new Error('enterprise-boot-html-size')
  }
  const kernel = html.indexOf('window.__ModuleLoader__={')
  const kernelGuard = html.indexOf(
    'client-modules: HTML did not preload @deepseek-ai/dsh-client-modules/client.js',
  )
  const graphMarker = html.indexOf('globalThis["__DSH_BOOT__"] = ')
  if (kernel < 0 || kernelGuard < kernel || graphMarker < kernelGuard) {
    throw new Error('enterprise-client-module-kernel-missing')
  }
  const graph = parseBootGraph(html)
  const moduleRows = graph.entries.filter(row =>
    row !== null && typeof row === 'object' && row.id === clientModulesId)
  const moduleUrl = exactClientModulesUrl(moduleRows[0]?.rev, true)
  if (moduleRows.length !== 1
      || moduleUrl === undefined || moduleRows[0].url !== moduleUrl) {
    throw new Error('enterprise-client-module-graph-entry')
  }
  const bootstrapBatches = graph.batches.filter(batch =>
    batch !== null && typeof batch === 'object' && batch.phase === 'bootstrap')
  const bootstrap = bootstrapBatches[0]
  const bootstrapUrl = exactClientModulesUrl(bootstrap?.rev)
  const batchMemberships = graph.batches.reduce(
    (count, batch) => count + (Array.isArray(batch?.entries)
      ? batch.entries.filter(id => id === clientModulesId).length
      : 0),
    0,
  )
  if (bootstrapBatches.length !== 1 || !Array.isArray(bootstrap?.entries)
      || bootstrap.entries.length !== 1 || bootstrap.entries[0] !== clientModulesId
      || bootstrapUrl === undefined || bootstrap.url !== bootstrapUrl
      || batchMemberships !== 1) {
    throw new Error('enterprise-client-module-bootstrap-missing')
  }
  const bootstrapTag = `<script src="${bootstrap.url.replaceAll('&', '&amp;')}"></script>`
  const bootstrapScript = html.indexOf(bootstrapTag)
  if (bootstrapScript <= kernelGuard || bootstrapScript >= graphMarker
      || html.indexOf(bootstrapTag, bootstrapScript + 1) !== -1) {
    throw new Error('enterprise-client-module-bootstrap-script')
  }
  return graph
}

// Execute the locally built bootstrap in a time-bounded context with no Node
// APIs supplied. This is a behavior test of pinned build output, not a security
// sandbox for arbitrary code. Comments and formatting cannot create a second
// registration; the actual exported bootstrap face must be callable.
export function validateClientModuleBootstrapBundle(source) {
  if (typeof source !== 'string' || source.length === 0
      || Buffer.byteLength(source, 'utf8') > maximumBodyBytes) {
    throw new Error('enterprise-client-module-bundle-size')
  }
  try {
    const context = createContext(Object.create(null), {
      codeGeneration: { strings: false, wasm: false },
      microtaskMode: 'afterEvaluate',
    })
    const options = { timeout: 1000 }
    new Script(`
      const registrations = [];
      globalThis.window = {
        __ModuleLoader__: { load(record) { registrations.push(record); } }
      };
    `).runInContext(context, options)
    new Script(source).runInContext(context, options)
    const valid = new Script(`
      (() => {
        if (registrations.length !== 1) return false;
        const record = registrations[0];
        if (record === null || typeof record !== 'object'
            || record.id !== '@deepseek-ai/dsh-client-modules'
            || typeof record.factory !== 'function') return false;
        let externalRequests = 0;
        const face = record.factory(() => {
          externalRequests++;
          throw new Error('external bootstrap dependency');
        });
        return externalRequests === 0 && registrations.length === 1
          && face !== null && typeof face === 'object'
          && typeof face.apply === 'function'
          && typeof face.createClientModuleSystem === 'function';
      })()
    `).runInContext(context, options)
    if (valid !== true) throw new Error('invalid bootstrap face')
  } catch {
    // Preserve fixed diagnostics; never return exception text from bundle code.
    throw new Error('enterprise-client-module-bundle-registration')
  }
}

async function fetchClientModuleBootstrap(baseUrl, cookie, graph) {
  const bootstrap = graph.batches.find(batch => batch?.phase === 'bootstrap')
  if (bootstrap === undefined || bootstrap.url !== exactClientModulesUrl(bootstrap.rev)) {
    throw new Error('enterprise-client-module-bundle-url')
  }
  let assetUrl
  try {
    assetUrl = new URL(bootstrap.url, baseUrl)
  } catch {
    throw new Error('enterprise-client-module-bundle-url')
  }
  if (assetUrl.origin !== baseUrl || assetUrl.username !== '' || assetUrl.password !== ''
      || assetUrl.hash !== '') {
    throw new Error('enterprise-client-module-bundle-origin')
  }
  const response = await fetch(assetUrl, {
    redirect: 'manual',
    headers: { cookie },
    signal: AbortSignal.timeout(15_000),
  })
  if (response.status !== 200
      || response.headers.get('content-type')?.toLowerCase() !== 'text/javascript; charset=utf-8'
      || response.headers.get('location') !== null
      || response.headers.getSetCookie().length !== 0) {
    throw new Error('enterprise-client-module-bundle-http')
  }
  validateClientModuleBootstrapBundle(
    await readBoundedText(response, 'enterprise-client-module-bundle'),
  )
}

function assertRefused(node, args, environment, workspace, expected) {
  const result = spawnSync(node, args, {
    cwd: workspace,
    env: environment,
    windowsHide: true,
    encoding: 'utf8',
    timeout: 30_000,
    maxBuffer: 1024 * 1024,
  })
  const output = String(result.stdout ?? '') + '\n' + String(result.stderr ?? '')
  if (result.error !== undefined || result.status === 0 || !output.includes(expected)) {
    throw new Error('enterprise-direct-local-refusal-contract')
  }
}

async function assertAuthenticationRejected(baseUrl, cookie, label) {
  const headers = cookie === undefined ? {} : { cookie }
  const root = await fetch(baseUrl + '/', {
    redirect: 'manual',
    headers,
    signal: AbortSignal.timeout(10_000),
  })
  if (root.status !== 401 || root.headers.get('location') !== null
      || root.headers.getSetCookie().length !== 0) {
    throw new Error(label + '-root-auth-rejection')
  }
  await readBoundedText(root, label + '-root-rejection')

  const rpcId = randomUUID()
  const api = await fetch(baseUrl + '/api/settings/describe', {
    method: 'POST',
    redirect: 'manual',
    headers: { ...headers, 'content-type': 'application/json' },
    body: JSON.stringify({
      type: 'client-request',
      rpcId,
      method: 'settings/describe',
      payload: { args: {} },
    }),
    signal: AbortSignal.timeout(10_000),
  })
  if (api.status !== 401 || api.headers.get('location') !== null
      || api.headers.getSetCookie().length !== 0) {
    throw new Error(label + '-api-auth-rejection')
  }
  await readBoundedText(api, label + '-api-rejection')
}

async function remoteCall(baseUrl, cookie, method, args) {
  const rpcId = randomUUID()
  const response = await fetch(baseUrl + '/api/' + method, {
    method: 'POST',
    redirect: 'manual',
    headers: { cookie, 'content-type': 'application/json' },
    body: JSON.stringify({
      type: 'client-request',
      rpcId,
      method,
      payload: { args },
    }),
    signal: AbortSignal.timeout(15_000),
  })
  if (response.status < 200 || response.status >= 300
      || !response.headers.get('content-type')?.toLowerCase().startsWith('application/json')) {
    throw new Error('enterprise-direct-local-rpc-http')
  }
  let envelope
  try {
    envelope = JSON.parse(await readBoundedText(response, 'enterprise-direct-local-rpc'))
  } catch {
    throw new Error('enterprise-direct-local-rpc-json')
  }
  if (envelope === null || typeof envelope !== 'object' || Array.isArray(envelope)
      || envelope.type !== 'server-response' || envelope.rpcId !== rpcId
      || envelope.result?.ok !== true) {
    throw new Error('enterprise-direct-local-rpc-envelope')
  }
  return envelope.result.value
}

function assertFixedProviderSettings(settings) {
  if (settings === null || typeof settings !== 'object' || Array.isArray(settings)
      || settings.writable !== false || settings.hasDocument !== false
      || !Array.isArray(settings.namespaces)) {
    throw new Error('enterprise-direct-local-settings-capability')
  }
  const namespaces = new Map(settings.namespaces.map(row => [row?.ns, row]))
  const model = namespaces.get('llm-deepseek')?.value
  const search = namespaces.get('web-search-deepseek')?.value
  if (model?.baseURL !== 'https://api.deepseek.com'
      || model?.apiKeyEnv !== 'DEEPSEEK_API_KEY'
      || search?.baseURL !== 'https://api.deepseek.com/anthropic/v1'
      || search?.apiKeyEnv !== 'DEEPSEEK_API_KEY') {
    throw new Error('enterprise-direct-local-fixed-provider')
  }
}

function copyEnvironmentValue(environment, key) {
  const found = Object.entries(process.env)
    .find(([name]) => name.toLowerCase() === key.toLowerCase())
  if (found !== undefined) environment[key] = found[1]
}

export async function runSmoke(runtime, smokeRoot, onStage = () => {}) {
  const stage = value => {
    if (!diagnosticStages.has(value)) throw new Error('invalid-diagnostic-stage')
    onStage(value)
  }
  stage('runtime-layout')
  assert.equal(process.platform, 'win32')
  assert.ok(isAbsolute(runtime) && isAbsolute(smokeRoot))
  runtime = resolve(runtime)
  smokeRoot = resolve(smokeRoot)
  const node = join(runtime, 'node.exe')
  const entry = join(runtime, 'node_modules', '@deepseek-ai', 'dsh', 'lib', 'bin.js')
  for (const path of [runtime, node, entry]) {
    const info = await lstat(path)
    assert.equal(info.isSymbolicLink(), false)
  }
  stage('smoke-root')
  await mkdir(smokeRoot)
  assert.equal(await realpath(smokeRoot), smokeRoot)
  const workspace = join(smokeRoot, 'workspaces')
  const skillsRoot = join(smokeRoot, 'skills')
  await mkdir(workspace)
  await mkdir(skillsRoot)
  assert.equal(await realpath(skillsRoot), skillsRoot)

  const instance = randomUUID()
  const pipeName = '\\\\.\\pipe\\ensou-dsh-update-' + instance.replaceAll('-', '')
  const pipe = createServer()
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
  const deadline = setTimeout(() => fail(new Error('enterprise-direct-local-smoke-deadline')), 180_000)
  const bounded = operation => Promise.race([operation, fatal])
  pipe.on('error', fail)
  pipe.on('connection', incoming => {
    if (socket !== undefined) {
      incoming.destroy()
      fail(new Error('duplicate-update-client'))
      return
    }
    socket = incoming
    incoming.on('error', fail)
    incoming.on('close', () => {
      if (!shutdownExpected || responseWaiter !== undefined) fail(new Error('update-channel-closed'))
    })
    incoming.on('data', bytes => {
      if (responseWaiter === undefined) {
        fail(new Error('unsolicited-update-response'))
        return
      }
      pending = Buffer.concat([pending, bytes])
      if (pending.length > 8192) {
        fail(new Error('unbounded-update-response'))
        return
      }
      const newline = pending.indexOf(10)
      if (newline < 0) return
      if (newline !== pending.length - 1) {
        fail(new Error('unsolicited-update-response'))
        return
      }
      const accept = responseWaiter
      responseWaiter = undefined
      try {
        const text = new TextDecoder('utf-8', { fatal: true }).decode(pending.subarray(0, newline))
        pending = Buffer.alloc(0)
        accept(text)
      } catch (error) {
        fail(error)
      }
    })
    connectResolve()
  })

  try {
    stage('update-pipe-listen')
    await bounded(listen(pipe, pipeName))
    const webPort = await bounded(reservePort())
    const environment = {}
    for (const key of [
      'SystemRoot', 'WINDIR', 'ComSpec', 'SystemDrive',
      'ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432',
    ]) copyEnvironmentValue(environment, key)
    const system32 = join(environment.SystemRoot, 'System32')
    for (const key of ['USERPROFILE', 'HOME', 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP']) {
      environment[key] = join(smokeRoot, key)
      await mkdir(environment[key])
    }
    Object.assign(environment, {
      PATH: [runtime, system32, join(system32, 'Wbem'), join(system32, 'WindowsPowerShell', 'v1.0')]
        .join(';'),
      DSH_HOME: join(smokeRoot, '.dsh'),
      DSH_AGENTS_HOME: join(smokeRoot, '.agents'),
      DSH_TELEMETRY_DISABLED: '1',
      DSH_ENTERPRISE_MANAGED_BOOT: managedBootMarker,
      ENSOU_DSH_ENTERPRISE_SKILLS_ROOT: skillsRoot,
      ENSOU_DSH_UPDATE_PIPE: pipeName,
      ENSOU_DSH_RUNTIME_INSTANCE_ID: instance,
      NO_PROXY: '127.0.0.1,localhost,::1',
    })
    const exactArguments = [
      entry, '--profile', 'enterprise-direct-local',
      '--host', '127.0.0.1', '--port', String(webPort),
    ]

    stage('launch-refusals')
    const refusalEnvironment = { ...environment }
    delete refusalEnvironment.ENSOU_DSH_UPDATE_PIPE
    delete refusalEnvironment.ENSOU_DSH_RUNTIME_INSTANCE_ID
    const noMarker = { ...refusalEnvironment }
    delete noMarker.DSH_ENTERPRISE_MANAGED_BOOT
    assertRefused(
      node, exactArguments, noMarker, workspace, 'requires the enterprise Launcher')
    assertRefused(
      node,
      [entry, '--profile', 'web', '--host', '127.0.0.1', '--port', String(webPort)],
      refusalEnvironment,
      workspace,
      'may boot only profile',
    )
    assertRefused(
      node,
      [...exactArguments, '--trusted-host', 'attacker.invalid'],
      refusalEnvironment,
      workspace,
      'must provide exactly --host 127.0.0.1',
    )

    stage('runtime-spawn')
    child = spawn(node, exactArguments, {
      cwd: workspace,
      env: environment,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    child.once('error', fail)
    const exited = new Promise(accept =>
      child.once('exit', (code, signal) => accept({ code, signal })))
    let outputBytes = 0
    let readinessTail = ''
    let launchResolve
    const launchUrlReady = new Promise(accept => { launchResolve = accept })
    for (const stream of [child.stdout, child.stderr]) {
      stream.on('error', fail)
      stream.on('data', data => {
        outputBytes += data.length
        if (outputBytes > 8 * 1024 * 1024) {
          fail(new Error('runtime-log-limit'))
          return
        }
        if (launchResolve === undefined) return
        readinessTail = (readinessTail + data.toString()).slice(-16_384)
        const match = /dsh web: (http:\/\/127\.0\.0\.1:\d+\/\?token=[A-Za-z0-9_-]{43})(?:\r?\n|$)/
          .exec(readinessTail)
        if (match?.[1] !== undefined) {
          const accept = launchResolve
          launchResolve = undefined
          readinessTail = ''
          accept(match[1])
        }
      })
    }
    const prematureExit = exited.then(() => { throw new Error('runtime-exited-before-ready') })
    stage('runtime-readiness-url')
    const launchUrl = await bounded(Promise.race([launchUrlReady, prematureExit]))
    stage('update-pipe-connect')
    await bounded(Promise.race([connected, prematureExit]))
    stage('launch-url-contract')
    const expectedBaseUrl = 'http://127.0.0.1:' + String(webPort)
    const parsedLaunch = new URL(launchUrl)
    if (parsedLaunch.origin !== expectedBaseUrl || parsedLaunch.pathname !== '/'
        || !/^[A-Za-z0-9_-]{43}$/.test(parsedLaunch.searchParams.get('token') ?? '')
        || parsedLaunch.searchParams.size !== 1) {
      throw new Error('enterprise-direct-local-auth-url-contract')
    }

    stage('anonymous-auth')
    await assertAuthenticationRejected(expectedBaseUrl, undefined, 'anonymous')
    stage('token-exchange')
    const exchange = await fetch(launchUrl, {
      redirect: 'manual',
      signal: AbortSignal.timeout(10_000),
    })
    const setCookies = exchange.headers.getSetCookie()
    if (exchange.status !== 303 || exchange.headers.get('location') !== '/'
        || exchange.headers.get('cache-control') !== 'no-store'
        || exchange.headers.get('referrer-policy') !== 'no-referrer'
        || setCookies.length !== 1) {
      throw new Error('enterprise-direct-local-token-exchange')
    }
    const cookie = validateBrowserSetCookie(setCookies[0], parsedLaunch.host)
    const forgedCookie = cookie.slice(0, -1) + (cookie.endsWith('A') ? 'B' : 'A')
    stage('forged-auth')
    await assertAuthenticationRejected(expectedBaseUrl, forgedCookie, 'forged')

    stage('authenticated-root')
    const root = await fetch(expectedBaseUrl + '/', {
      redirect: 'manual',
      headers: { cookie },
      signal: AbortSignal.timeout(15_000),
    })
    if (root.status !== 200) throw new Error('authenticated-enterprise-root-http')
    stage('kernel-bootstrap')
    const bootGraph = validateEnterpriseBootHtml(
      await readBoundedText(root, 'authenticated-enterprise-root'),
    )
    await fetchClientModuleBootstrap(expectedBaseUrl, cookie, bootGraph)

    stage('settings-capability')
    const settings = await remoteCall(expectedBaseUrl, cookie, 'settings/describe', {})
    assertFixedProviderSettings(settings)
    stage('credential-cycle')
    const ref = 'DEEPSEEK_API_KEY'
    const before = await remoteCall(
      expectedBaseUrl, cookie, 'credentials/describe', { refs: [ref] })
    if (before?.[ref]?.configured !== false || before?.[ref]?.writable !== true) {
      throw new Error('enterprise-direct-local-credential-initial')
    }
    const synthetic = 'synthetic-runtime-smoke-' + randomUUID()
    await remoteCall(expectedBaseUrl, cookie, 'credentials/set', { ref, value: synthetic })
    const configured = await remoteCall(
      expectedBaseUrl, cookie, 'credentials/describe', { refs: [ref] })
    if (configured?.[ref]?.configured !== true || configured?.[ref]?.source !== 'file'
        || configured?.[ref]?.writable !== true) {
      throw new Error('enterprise-direct-local-credential-write')
    }
    await remoteCall(expectedBaseUrl, cookie, 'credentials/unset', { ref })
    const after = await remoteCall(
      expectedBaseUrl, cookie, 'credentials/describe', { refs: [ref] })
    if (after?.[ref]?.configured !== false || after?.[ref]?.writable !== true) {
      throw new Error('enterprise-direct-local-credential-unset')
    }

    const identity = { instance, pid: child.pid }
    const request = async (action, operationId) => {
      assert.equal(responseWaiter, undefined)
      const response = new Promise(accept => { responseWaiter = accept })
      socket.write(JSON.stringify({
        protocol: updateProtocol,
        runtimeInstanceId: instance,
        operationId,
        action,
      }) + '\n')
      try {
        return validateReceipt(
          await bounded(within(response, 15_000, 'update-response-timeout')),
          identity,
          operationId,
        )
      } finally {
        responseWaiter = undefined
      }
    }
    const drain = async operationId => {
      let receipt = await request('drain', operationId)
      while (receipt.phase === 'draining') {
        await bounded(new Promise(accept => setTimeout(accept, 50)))
        receipt = await request('status', operationId)
      }
      assert.equal(receipt.phase, 'ready')
    }
    const first = randomUUID()
    stage('update-cycle-1-drain')
    await drain(first)
    stage('update-cycle-1-resume')
    assert.equal((await request('resume', first)).phase, 'resumed')
    const second = randomUUID()
    stage('update-cycle-2-drain')
    await drain(second)
    shutdownExpected = true
    stage('update-cycle-2-shutdown')
    assert.equal((await request('shutdown', second)).phase, 'ready')
    stage('runtime-exit')
    assert.deepEqual(await bounded(exited), { code: 0, signal: null })

    return {
      status: 'PASS',
      resultStatus: 'PASS',
      scope: 'BUILT_ENTERPRISE_DIRECT_LOCAL_RUNTIME_CAPABILITY_ONLY',
      cycles: 2,
      kernelBootstrapVerified: true,
      settingsReadOnly: true,
      credentialsWritable: true,
      exactChildExited: true,
      authenticationNegativesVerified: true,
      launchRefusalsVerified: true,
      modelRequestsSent: 0,
      outputBytes,
    }
  } finally {
    clearTimeout(deadline)
    socket?.destroy()
    const serverCleanup = closeServer(pipe)
    void serverCleanup.catch(() => {})
    if (child !== undefined && child.exitCode === null && child.signalCode === null) {
      child.kill()
      await within(
        new Promise(accept => child.once('exit', accept)),
        5000,
        'synthetic-child-cleanup-timeout',
      )
    }
    await serverCleanup
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  let failureStage = 'unclassified'
  try {
    const [runtime, smokeRoot] = process.argv.slice(2)
    if (runtime === undefined || smokeRoot === undefined || process.argv.length !== 4) {
      throw new Error('usage')
    }
    console.log(JSON.stringify(await runSmoke(runtime, smokeRoot, stage => { failureStage = stage })))
  } catch (error) {
    console.error(JSON.stringify(createFailureReceipt(failureStage, error)))
    process.exitCode = 1
  }
}
