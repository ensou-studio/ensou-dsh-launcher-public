import assert from 'node:assert/strict'
import test from 'node:test'
import {
  createFailureReceipt,
  validateClientModuleBootstrapBundle,
  validateEnterpriseBootHtml,
  validateReceipt,
} from './Test-EnterpriseDirectLocalRuntimeSmoke.mjs'

test('failure receipts expose only one fixed diagnostic stage', () => {
  assert.deepEqual(createFailureReceipt('runtime-readiness-url', new Error('secret token=value')), {
    status: 'FAIL',
    resultStatus: 'FAIL',
    failureType: 'Error',
    failureStage: 'runtime-readiness-url',
  })
  assert.deepEqual(createFailureReceipt('not-a-stage', { constructor: { name: 'Injected' } }), {
    status: 'FAIL',
    resultStatus: 'FAIL',
    failureType: 'Error',
    failureStage: 'unclassified',
  })
})

const graph = {
  rev: '111111111111',
  entries: [{
    id: '@deepseek-ai/dsh-client-modules',
    url: '/plugins/??@deepseek-ai/dsh-client-modules/client.js&rev=222222222222',
    rev: '222222222222',
  }],
  batches: [{
    phase: 'bootstrap',
    entries: ['@deepseek-ai/dsh-client-modules'],
    url: '/plugins/??@deepseek-ai/dsh-client-modules/client.js&rev=333333333333',
    rev: '333333333333',
  }],
}
const kernel = [
  '<html><head><script>',
  'window.__ModuleLoader__={',
  'create(){throw new Error("client-modules: HTML did not preload @deepseek-ai/dsh-client-modules/client.js")}',
  '}</script>',
  '<script src="/plugins/??@deepseek-ai/dsh-client-modules/client.js&amp;rev=333333333333"></script>',
  '<script>',
  'globalThis["__DSH_BOOT__"] = ' + JSON.stringify(graph),
  '</script></head></html>',
].join('')

test('accepts an authenticated boot document only with the client-module kernel', () => {
  assert.equal(
    validateEnterpriseBootHtml(kernel).batches[0].entries[0],
    '@deepseek-ai/dsh-client-modules',
  )
  assert.throws(
    () => validateEnterpriseBootHtml(kernel.replace('window.__ModuleLoader__={', 'window.__Omitted__={')),
    /kernel-missing/,
  )
})

test('accepts the pinned runtime opaque initial row revision separately from a batch hash', () => {
  // ClientModules.allocateInitialRevision uses an eight-byte hex nonce plus
  // a decimal counter. buildBatch independently hashes its complete artifact.
  const rev = '0123456789abcdef-0'
  const initialGraph = {
    ...graph,
    entries: [{
      ...graph.entries[0],
      rev,
      url: `/plugins/??@deepseek-ai/dsh-client-modules/client.js&rev=${rev}`,
    }],
  }
  const initialHtml = kernel.replace(JSON.stringify(graph), JSON.stringify(initialGraph))
  assert.equal(validateEnterpriseBootHtml(initialHtml).entries[0].rev, rev)
})

test('rejects noncanonical or unsafe initial revisions and a missing row URL', () => {
  for (const rev of [
    '', 'ABCDEF0123456789-0', '0123456789abcdef-', '0123456789abcdef-01',
    '0123456789abcdef--1', '0123456789abcdef-1.0', '0123456789abcdef-1e2',
    '0123456789abcdef-9007199254740992', '0123456789abcdef-0&extra=1',
    '0123456789abcdef-0#fragment', '0123456789abcdef-0\n',
    undefined, null, 0, [], {},
  ]) {
    const invalid = {
      ...graph,
      entries: [{ ...graph.entries[0], rev, url: rev === undefined ? undefined
        : `/plugins/??@deepseek-ai/dsh-client-modules/client.js&rev=${String(rev)}` }],
    }
    assert.throws(() => validateEnterpriseBootHtml(
      kernel.replace(JSON.stringify(graph), JSON.stringify(invalid)),
    ), /graph-entry/)
  }
})

test('does not accept the initial-row revision format for a bootstrap batch', () => {
  const rev = '0123456789abcdef-0'
  const invalid = {
    ...graph,
    batches: [{ ...graph.batches[0], rev,
      url: `/plugins/??@deepseek-ai/dsh-client-modules/client.js&rev=${rev}` }],
  }
  assert.throws(() => validateEnterpriseBootHtml(
    kernel.replace(JSON.stringify(graph), JSON.stringify(invalid)),
  ), /bootstrap-missing/)
})

test('rejects a graph that omits the client-module bootstrap entry', () => {
  const omitted = kernel.replace(
    JSON.stringify(graph),
    JSON.stringify({ ...graph, batches: [{ ...graph.batches[0], entries: [] }] }),
  )
  assert.throws(() => validateEnterpriseBootHtml(omitted), /bootstrap-missing/)
})

test('rejects missing and duplicate client-module graph rows', () => {
  for (const entries of [
    [],
    [...graph.entries, graph.entries[0]],
    [{ ...graph.entries[0], url: '/plugins/??@fixture/unrelated/client.js&rev=222222222222' }],
  ]) {
    const invalid = kernel.replace(
      JSON.stringify(graph),
      JSON.stringify({ ...graph, entries }),
    )
    assert.throws(() => validateEnterpriseBootHtml(invalid), /graph-entry/)
  }
})

test('rejects a missing or duplicate blocking bootstrap script', () => {
  const tag = '<script src="/plugins/??@deepseek-ai/dsh-client-modules/client.js&amp;rev=333333333333"></script>'
  assert.throws(() => validateEnterpriseBootHtml(kernel.replace(tag, '')), /bootstrap-script/)
  assert.throws(() => validateEnterpriseBootHtml(kernel.replace(tag, tag + tag)), /bootstrap-script/)
})

const validBundle = [
  'window.__ModuleLoader__.load({',
  '  id: "@deepseek-ai/dsh-client-modules",',
  '  factory: (require) => {',
  '    var exports = {};',
  '    function apply() {}',
  '    function createClientModuleSystem() {}',
  '    exports.apply = apply;',
  '    exports.createClientModuleSystem = createClientModuleSystem;',
  '    return exports;',
  '  }',
  '});',
].join('\n')

test('accepts only the actual client-module bootstrap registration face', () => {
  assert.doesNotThrow(() => validateClientModuleBootstrapBundle(validBundle))
  for (const invalid of [
    '',
    'console.log("unrelated")',
    validBundle.replace('@deepseek-ai/dsh-client-modules', '@fixture/unrelated'),
    validBundle.replace('exports.apply = apply;', ''),
    validBundle.replace('exports.createClientModuleSystem = createClientModuleSystem;', ''),
    validBundle + '\nwindow.__ModuleLoader__.load({ id: "@fixture/extra", factory: () => ({}) });',
  ]) {
    assert.throws(() => validateClientModuleBootstrapBundle(invalid))
  }
})

test('counts executed bootstrap registrations rather than examples in comments', () => {
  const documentedBundle = validBundle.replace('var exports = {};', [
    '// A factory registers via window.__ModuleLoader__.load({ id, factory }).',
    'var exports = {};',
  ].join('\n'))
  assert.doesNotThrow(() => validateClientModuleBootstrapBundle(documentedBundle))
})

test('executes the bootstrap factory and rejects invalid faces and external dependencies', () => {
  for (const invalid of [
    validBundle.replace('exports.apply = apply;', 'exports.apply = true;'),
    validBundle.replace('exports.createClientModuleSystem = createClientModuleSystem;',
      'exports.createClientModuleSystem = "not a function";'),
    validBundle.replace('return exports;', 'return null;'),
    validBundle.replace('return exports;', 'return {};'),
    validBundle.replace('return exports;', 'return require("unexpected");'),
    validBundle.replace('return exports;', 'try { require("unexpected"); } catch {} return exports;'),
    validBundle.replace('return exports;', 'throw new Error("secret synthetic token");'),
    validBundle.replace('return exports;', 'return process.env;'),
    validBundle.replace('return exports;', 'return fetch("https://invalid.example");'),
    validBundle.replace('return exports;', 'return eval("({})");'),
    validBundle.replace('return exports;',
      'window.__ModuleLoader__.load({ id: "extra", factory: () => ({}) }); return exports;'),
  ]) {
    assert.throws(() => validateClientModuleBootstrapBundle(invalid), {
      message: 'enterprise-client-module-bundle-registration',
    })
  }
})

test('bounds an unfinished bootstrap factory without exposing its errors', () => {
  assert.throws(() => validateClientModuleBootstrapBundle(
    validBundle.replace('return exports;', 'while (true) {}'),
  ), { message: 'enterprise-client-module-bundle-registration' })
})

test('rejects a private update receipt from the wrong runtime identity', () => {
  const identity = { instance: 'f03d809d-156e-4bde-8411-71dca65d684d', pid: 4312 }
  const operationId = 'ae3d880d-f2de-4590-ac5c-98dd3a2c21da'
  const receipt = {
    protocol: 'ensou.dsh.runtime-update.v1',
    runtimeInstanceId: '11111111-1111-1111-1111-111111111111',
    processId: identity.pid,
    operationId,
    phase: 'ready',
    activeOperations: 0,
    persistenceFlushed: true,
  }
  assert.throws(() => validateReceipt(JSON.stringify(receipt), identity, operationId))
})
