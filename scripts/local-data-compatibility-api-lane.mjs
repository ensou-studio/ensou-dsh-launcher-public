import { createHash, randomUUID } from 'node:crypto'
import { createServer } from 'node:http'
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { spawn } from 'node:child_process'

const configPath = process.argv[2]
if (!configPath) throw new Error('one JSON config path is required')
const config = JSON.parse(await readFile(configPath, 'utf8'))

const utf8 = value => Buffer.from(value, 'utf8')
const sha256 = value => createHash('sha256').update(value).digest('hex')
const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds))
const deadline = () => Date.now() + config.timeoutSeconds * 1_000
const sanitize = value => String(value)
  .replaceAll('fixture-only-value', '<redacted-fixture-value>')
  .replaceAll('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', '<redacted-fixture-api-key>')

async function ensureParent(path) {
  await mkdir(dirname(path), { recursive: true })
}

async function writeJson(path, value) {
  await ensureParent(path)
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, 'utf8')
}

function assistantText(body) {
  const text = JSON.stringify(body)
  const pairs = [
    [config.markers.sourcePrompt, config.markers.sourceResponse],
    [config.markers.targetPrompt, config.markers.targetResponse],
    [config.markers.restoredPrompt, config.markers.restoredResponse],
  ]
  const preferredIndex = { 'source-seed': 0, 'target-forward': 1, 'source-restored': 2 }[config.phase]
  if (preferredIndex !== undefined) pairs.unshift(pairs.splice(preferredIndex, 1)[0])
  for (const pair of pairs) {
    if (text.includes(pair[0])) return pair[1]
  }
  return 'compatproviderfallbackack'
}

function imageProjections(body) {
  const projections = []
  function visit(value) {
    if (Array.isArray(value)) {
      for (const item of value) visit(item)
      return
    }
    if (value === null || typeof value !== 'object') return
    if (value.type === 'image_url' && typeof value.image_url?.url === 'string') {
      const match = /^data:([^;,]+);base64,([A-Za-z0-9+/=]+)$/.exec(value.image_url.url)
      if (match) {
        const data = Buffer.from(match[2], 'base64')
        projections.push({
          mode: 'inline-data-url',
          mediaType: match[1],
          bytes: data.length,
          sha256: sha256(data),
        })
      } else {
        projections.push({ mode: 'non-inline-image-url' })
      }
    } else if (value.type === 'file' && typeof value.file_id === 'string') {
      projections.push({ mode: 'provider-file-id', fileIdSha256: sha256(utf8(value.file_id)) })
    }
    for (const child of Object.values(value)) visit(child)
  }
  visit(body)
  return projections
}

async function startProvider() {
  const requests = []
  let nextFile = 1
  const files = new Map()
  const server = createServer((request, response) => {
    const chunks = []
    request.on('data', chunk => chunks.push(chunk))
    request.on('end', () => {
      try {
        const url = new URL(request.url ?? '/', 'http://127.0.0.1')
        const body = Buffer.concat(chunks)
        if (url.pathname.endsWith('/files') && request.method === 'POST') {
          const createdAt = Math.floor(Date.now() / 1_000)
          const id = `compat-file-${nextFile++}`
          const file = {
            id,
            object: 'file',
            bytes: Math.max(1, body.length),
            created_at: createdAt,
            filename: 'compat-image.png',
            purpose: 'user_data',
            expires_at: createdAt + 86_400,
          }
          files.set(id, file)
          requests.push({ method: request.method, path: url.pathname, kind: 'file-upload', bytes: body.length })
          response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(file))
          return
        }
        if (url.pathname.endsWith('/files') && request.method === 'GET') {
          const data = [...files.values()]
          requests.push({ method: request.method, path: `${url.pathname}${url.search}`, kind: 'file-list' })
          response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({
            object: 'list', data, first_id: data[0]?.id, last_id: data.at(-1)?.id, has_more: false,
          }))
          return
        }
        const fileMatch = url.pathname.match(/\/files\/([^/]+)$/)
        if (fileMatch && request.method === 'GET') {
          const file = files.get(decodeURIComponent(fileMatch[1]))
          requests.push({ method: request.method, path: url.pathname, kind: 'file-read' })
          response.writeHead(file ? 200 : 404, { 'content-type': 'application/json' })
            .end(JSON.stringify(file ?? { error: { message: 'file not found', code: 'file_not_found' } }))
          return
        }
        if (fileMatch && request.method === 'DELETE') {
          const id = decodeURIComponent(fileMatch[1])
          files.delete(id)
          requests.push({ method: request.method, path: url.pathname, kind: 'file-delete' })
          response.writeHead(200, { 'content-type': 'application/json' })
            .end(JSON.stringify({ id, object: 'file', deleted: true }))
          return
        }

        const parsed = body.length === 0 ? {} : JSON.parse(body.toString('utf8'))
        const text = assistantText(parsed)
        const projections = imageProjections(parsed)
        requests.push({
          method: request.method,
          path: url.pathname,
          kind: 'chat-completions',
          model: typeof parsed.model === 'string' ? parsed.model : null,
          stream: parsed.stream === true,
          responseMarker: text,
          requestSha256: sha256(body),
          imageProjectionCount: projections.length,
          imageProjections: projections,
        })
        response.writeHead(200, { 'content-type': 'text/event-stream' })
        const events = [
          { choices: [{ delta: { role: 'assistant', content: null, reasoning_content: '' } }] },
          { choices: [{ delta: { content: text } }] },
          { choices: [{ delta: { content: '' }, finish_reason: 'stop' }], usage: { prompt_tokens: 7, completion_tokens: 3 } },
        ]
        for (const event of events) response.write(`data: ${JSON.stringify(event)}\n\n`)
        response.end('data: [DONE]\n\n')
      } catch (error) {
        response.writeHead(500, { 'content-type': 'application/json' })
          .end(JSON.stringify({ error: { message: sanitize(error) } }))
      }
    })
  })
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('fake provider did not bind a TCP port')
  return {
    url: `http://127.0.0.1:${address.port}/v1`,
    requests,
    close: () => new Promise(resolve => server.close(resolve)),
  }
}

function startRuntime(providerUrl) {
  const env = { ...process.env }
  for (const name of Object.keys(env)) {
    if (/^(DSH_|DEEPSEEK_|ENSOU_DSH_|ANTHROPIC_|OPENAI_)/i.test(name)) delete env[name]
  }
  Object.assign(env, {
    DSH_ENTERPRISE_MANAGED_BOOT: 'ensou-dsh-launcher/v1',
    DSH_HOME: config.homeRoot,
    DSH_AGENTS_HOME: config.agentsHome,
    ENSOU_DSH_ENTERPRISE_SKILLS_ROOT: config.skillsRoot,
    DSH_TELEMETRY_DISABLED: '1',
    DEEPSEEK_BASE_URL: providerUrl,
    DEEPSEEK_SEARCH_BASE_URL: providerUrl,
    DEEPSEEK_API_KEY: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    NO_PROXY: '127.0.0.1,localhost',
    no_proxy: '127.0.0.1,localhost',
    BROWSER: 'none',
  })
  const child = spawn(config.nodePath, [
    config.entryPath,
    '--profile', 'enterprise-managed',
    '--host', '127.0.0.1',
    '--port', String(config.port),
  ], {
    cwd: config.workspace,
    env,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let stdout = ''
  let stderr = ''
  child.stdout.setEncoding('utf8')
  child.stderr.setEncoding('utf8')
  child.stdout.on('data', chunk => { stdout += chunk })
  child.stderr.on('data', chunk => { stderr += chunk })
  return { child, stdout: () => sanitize(stdout), stderr: () => sanitize(stderr) }
}

async function stopRuntime(runtime) {
  if (runtime.child.exitCode !== null) return
  runtime.child.kill('SIGTERM')
  const stopped = await Promise.race([
    new Promise(resolve => runtime.child.once('exit', () => resolve(true))),
    sleep(5_000).then(() => false),
  ])
  if (!stopped && runtime.child.exitCode === null) runtime.child.kill('SIGKILL')
}

async function waitReady(runtime) {
  const until = deadline()
  while (Date.now() < until) {
    if (runtime.child.exitCode !== null) {
      throw new Error(`runtime exited before readiness with code ${runtime.child.exitCode}: ${runtime.stderr().slice(-2_000)}`)
    }
    try {
      const rpcId = `compat-readiness-${randomUUID()}`
      const response = await fetch(`http://127.0.0.1:${config.port}/api/session.list`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ type: 'client-request', rpcId, method: 'session.list', payload: {} }),
      })
      if (response.status === 200) return
    } catch {}
    await sleep(100)
  }
  throw new Error('runtime did not become HTTP-ready before the deadline')
}

async function rpc(method, payload) {
  const rpcId = `compat-${randomUUID()}`
  const response = await fetch(`http://127.0.0.1:${config.port}/api/${method}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ type: 'client-request', rpcId, method, payload }),
  })
  if (!response.ok) throw new Error(`${method} transport returned HTTP ${response.status}`)
  const envelope = await response.json()
  if (envelope?.type !== 'server-response' || envelope.rpcId !== rpcId || !envelope.result) {
    throw new Error(`${method} returned a malformed or uncorrelated envelope`)
  }
  return envelope.result
}

async function rpcOk(method, payload) {
  const result = await rpc(method, payload)
  if (!result.ok) throw new Error(`${method} failed: ${result.error?.code ?? 'unknown'}: ${result.error?.message ?? ''}`)
  return result.value
}

async function history(sessionId) {
  return rpcOk('session.history', { sessionId, maxMessages: 100 })
}

async function waitHistoryContains(sessionId, required, forbidden = []) {
  const until = deadline()
  let latest
  while (Date.now() < until) {
    latest = await history(sessionId)
    const text = JSON.stringify(latest.events)
    if (required.every(token => text.includes(token)) && forbidden.every(token => !text.includes(token))) return latest
    await sleep(150)
  }
  throw new Error(`session.history did not reach required markers: ${required.join(', ')}`)
}

async function waitSearch(query, sessionId) {
  const until = deadline()
  let latest
  while (Date.now() < until) {
    const result = await rpc('session.search', { query })
    if (!result.ok) {
      const message = result.error?.message ?? ''
      if (result.error?.code === 'internal' && message.includes('session search is disabled') && message.includes('openAt "never"')) {
        return {
          mode: 'managed-disabled-public-api-policy',
          query,
          queryAttempted: true,
          errorCode: result.error.code,
          diagnosticClass: 'session-query-open-at-never',
          messageSha256: sha256(utf8(message)),
        }
      }
      throw new Error(`session.search failed: ${result.error.code}: ${message}`)
    }
    latest = result.value
    if (latest.items.some(item => item.sessionId === sessionId && item.snippet.includes(query))) {
      return {
        mode: 'result-items',
        query,
        queryAttempted: true,
        resultCount: latest.items.length,
      }
    }
    await sleep(150)
  }
  throw new Error(`session.search did not return ${sessionId} for ${query}`)
}

async function listFiles(root) {
  const found = []
  async function walk(path, relative) {
    let entries
    try { entries = await readdir(path, { withFileTypes: true }) } catch (error) {
      if (error?.code === 'ENOENT') return
      throw error
    }
    for (const entry of entries) {
      const child = join(path, entry.name)
      const childRelative = relative ? `${relative}/${entry.name}` : entry.name
      if (entry.isDirectory()) await walk(child, childRelative)
      else if (entry.isFile()) found.push(childRelative.replaceAll('\\', '/'))
    }
  }
  await walk(root, '')
  return found.sort()
}

async function exerciseAttachment() {
  const value = await rpcOk('session.attachment', {
    sessionId: config.attachmentSessionId,
    attachmentId: config.attachmentId,
  })
  const bytes = Buffer.from(value.data, 'base64')
  const objectSha = sha256(bytes)
  if (value.attachment.attachmentId !== `sha256:${objectSha}`) {
    throw new Error('session.attachment returned bytes that do not match the durable attachment id')
  }
  if (value.attachment.width !== 1 || value.attachment.height !== 1 || value.attachment.mediaType !== 'image/png') {
    throw new Error('session.attachment returned unexpected image metadata')
  }

  const selection = await rpc('session.selectModel', {
    sessionId: config.attachmentSessionId,
    provider: 'deepseek-official',
    model: 'deepseek-v4-flash-vision-exp',
  })
  let publicPolicyRefusal
  if (!selection.ok) {
    const message = selection.error?.message ?? ''
    if (selection.error?.code !== 'model-unavailable'
      || selection.error?.details?.provider !== 'deepseek-official'
      || selection.error?.details?.model !== 'deepseek-v4-flash-vision-exp') {
      throw new Error(`session.selectModel vision-policy refusal changed unexpectedly: ${selection.error?.code}: ${message}`)
    }
    publicPolicyRefusal = {
      stage: 'select-model',
      code: selection.error.code,
      diagnosticClass: 'managed-text-only-model-selection-refusal',
      messageSha256: sha256(utf8(message)),
      provider: 'deepseek-official',
      model: 'deepseek-v4-flash-vision-exp',
    }
  } else {
    if (selection.value.selected?.provider !== 'deepseek-official'
      || selection.value.selected?.model !== 'deepseek-v4-flash-vision-exp') {
      throw new Error('vision candidate selection returned an unexpected provider/model')
    }
    const marker = `compatattachmentpolicyrefusal-${config.phase}`
    const imagePrompt = await rpc('session.prompt', {
      sessionId: config.attachmentSessionId,
      mode: 'queue',
      content: [
        { type: 'text', text: marker },
        { type: 'image', mediaType: value.attachment.mediaType, data: value.data, name: 'compat-public-api.png' },
      ],
      clientTimeZone: 'Asia/Tokyo',
    })
    if (imagePrompt.ok) {
      throw new Error('local-data v1 forbids a successful image prompt on the managed profile')
    }
    const message = imagePrompt.error?.message ?? ''
    if (imagePrompt.error?.code !== 'attachment-error' || !message.includes('does not support image input')) {
      throw new Error(`session.prompt image policy refusal changed unexpectedly: ${imagePrompt.error?.code}: ${message}`)
    }
    publicPolicyRefusal = {
      stage: 'image-prompt',
      code: imagePrompt.error.code,
      diagnosticClass: 'managed-text-only-image-prompt-refusal',
      messageSha256: sha256(utf8(message)),
      provider: 'deepseek-official',
      model: 'deepseek-v4-flash-vision-exp',
    }
  }
  const expectedRefusal = config.phase === 'target-forward'
    ? { stage: 'image-prompt', code: 'attachment-error', diagnosticClass: 'managed-text-only-image-prompt-refusal' }
    : { stage: 'select-model', code: 'model-unavailable', diagnosticClass: 'managed-text-only-model-selection-refusal' }
  if (publicPolicyRefusal.stage !== expectedRefusal.stage
    || publicPolicyRefusal.code !== expectedRefusal.code
    || publicPolicyRefusal.diagnosticClass !== expectedRefusal.diagnosticClass) {
    throw new Error(`local-data v1 public refusal tuple changed for ${config.phase}`)
  }
  const requestImageFiles = await listFiles(join(config.homeRoot, 'attachments', 'v1', 'request-images'))
  if (requestImageFiles.length !== 0) {
    throw new Error('managed text-only image refusal materialized a request-image artifact')
  }
  const normalization = {
    status: 'not-applicable-managed-text-only-policy',
    publicPolicyRefusal,
    requestImageFiles,
  }
  return {
    publicApiRoundTripPassed: true,
    attachmentId: config.attachmentId,
    returnedBytes: bytes.length,
    returnedSha256: objectSha,
    metadata: value.attachment,
    requestImageNormalization: normalization,
  }
}

async function exercisePhase() {
  const sessionId = config.apiSessionId
  const source = config.markers
  const created = await rpcOk('session.create', {
    sessionId,
    workspaceId: config.workspaceId,
  })
  const before = await history(sessionId)
  const beforeText = JSON.stringify(before.events)
  const requiredBefore = config.phase === 'source-seed' ? [] : [source.sourcePrompt, source.sourceResponse]
  for (const marker of requiredBefore) {
    if (!beforeText.includes(marker)) throw new Error(`${config.phase} history omitted pre-upgrade marker ${marker}`)
  }
  if (config.phase === 'source-restored' && beforeText.includes(source.targetPrompt)) {
    throw new Error('restored source history retained the target-only prompt')
  }

  let promptMarker
  let responseMarker
  if (config.phase === 'source-seed') {
    promptMarker = source.sourcePrompt
    responseMarker = source.sourceResponse
  } else if (config.phase === 'target-forward') {
    promptMarker = source.targetPrompt
    responseMarker = source.targetResponse
  } else if (config.phase === 'source-restored') {
    promptMarker = source.restoredPrompt
    responseMarker = source.restoredResponse
  } else {
    throw new Error(`unknown API lane phase ${config.phase}`)
  }

  await rpcOk('session.prompt', {
    sessionId,
    mode: 'queue',
    content: [{ type: 'text', text: promptMarker }],
    clientTimeZone: 'Asia/Tokyo',
  })
  const after = await waitHistoryContains(sessionId, [...requiredBefore, promptMarker, responseMarker])
  const currentSearch = await waitSearch(promptMarker, sessionId)
  const sourceSearch = config.phase === 'source-seed'
    ? currentSearch
    : await waitSearch(source.sourcePrompt, sessionId)
  if (sourceSearch.mode !== currentSearch.mode) {
    throw new Error('session.search changed semantic mode between source and current marker queries')
  }
  if (currentSearch.mode === 'managed-disabled-public-api-policy' && (
    sourceSearch.errorCode !== currentSearch.errorCode ||
    sourceSearch.diagnosticClass !== currentSearch.diagnosticClass ||
    sourceSearch.messageSha256 !== currentSearch.messageSha256
  )) {
    throw new Error('session.search returned inconsistent managed-disabled semantics within one runtime phase')
  }
  const attachment = await exerciseAttachment()

  return {
    priorStateExpectationPassed: true,
    ...(config.phase === 'target-forward' ? { sourceMarkersPreserved: true } : {}),
    ...(config.phase === 'source-restored' ? { targetOnlyMarkerAbsentAfterRestore: true } : {}),
    sessionCreate: { passed: true, sessionId: created.sessionId, agentPreset: created.agentPreset ?? null },
    sessionApiResumeAppend: {
      passed: true,
      priorStateExpectationPassed: true,
      eventCountBefore: before.events.length,
      eventCountAfter: after.events.length,
      priorMarkersPreserved: requiredBefore,
      appendedPromptMarker: promptMarker,
      appendedProviderMarker: responseMarker,
    },
    conversationProviderRoundTrip: {
      passed: true,
      promptMarker,
      responseMarker,
    },
    sessionQuerySemanticParity: {
      passed: true,
      mode: currentSearch.mode,
      queryAttempted: true,
      errorCode: currentSearch.errorCode ?? null,
      diagnosticClass: currentSearch.diagnosticClass ?? null,
      messageSha256: currentSearch.messageSha256 ?? null,
      sessionId,
    },
    attachment,
  }
}

let provider
let runtime
let decision = 'FAIL'
let failure
let phaseResult
try {
  await mkdir(config.agentsHome, { recursive: true })
  await mkdir(config.skillsRoot, { recursive: true })
  provider = await startProvider()
  runtime = startRuntime(provider.url)
  await waitReady(runtime)
  phaseResult = await exercisePhase()
  decision = 'PASS'
} catch (error) {
  failure = {
    type: error?.constructor?.name ?? 'Error',
    message: sanitize(error?.message ?? error),
  }
} finally {
  if (runtime) await stopRuntime(runtime)
  if (provider) await provider.close()
  if (runtime) {
    await ensureParent(config.runtimeStdoutPath)
    await writeFile(config.runtimeStdoutPath, runtime.stdout(), 'utf8')
    await writeFile(config.runtimeStderrPath, runtime.stderr(), 'utf8')
  }
}

const providerRequests = provider?.requests ?? []
const result = {
  schemaVersion: 1,
  resultType: 'ensou-dsh-cross-runtime-api-lane-result',
  phase: config.phase,
  decision,
  runtimeArchiveSha256: config.runtimeArchiveSha256,
  runtimeBootPassed: runtime !== undefined && decision === 'PASS',
  ...(phaseResult ? { ...phaseResult } : {}),
  provider: {
    loopbackOnly: true,
    requestCount: providerRequests.length,
    chatCompletionCount: providerRequests.filter(request => request.kind === 'chat-completions').length,
    fileRequestCount: providerRequests.filter(request => request.kind.startsWith('file-')).length,
    requests: providerRequests,
  },
  ...(failure ? { failure } : {}),
  recordedAtUtc: new Date().toISOString(),
}
await writeJson(config.resultPath, result)
process.stdout.write(`${JSON.stringify({ decision, resultPath: config.resultPath, resultSha256: sha256(await readFile(config.resultPath)) })}\n`)
if (decision !== 'PASS') process.exitCode = 1
