import assert from 'node:assert/strict'
import test from 'node:test'
import { validateReceipt } from './Test-PersonalManagedRuntimeSmoke.mjs'

const identity = { instance: 'f03d809d-156e-4bde-8411-71dca65d684d', pid: 123 }
const operation = 'ae3d880d-f2de-4590-ac5c-98dd3a2c21da'
const receipt = {
  protocol: 'ensou.dsh.runtime-update.v1', runtimeInstanceId: identity.instance,
  processId: identity.pid, operationId: operation, phase: 'ready', activeOperations: 0, persistenceFlushed: true,
}

test('accepts only the launched child and exact update cycle', () => {
  assert.equal(validateReceipt(JSON.stringify(receipt), identity, operation).phase, 'ready')
  for (const patch of [{ processId: 124 }, { runtimeInstanceId: operation }, { operationId: identity.instance }]) {
    assert.throws(() => validateReceipt(JSON.stringify({ ...receipt, ...patch }), identity, operation))
  }
})
test('ready requires flushed persistence and zero active work', () => {
  for (const patch of [{ activeOperations: 1 }, { activeOperations: -1 }, { persistenceFlushed: false }, { phase: 'unknown' }]) {
    assert.throws(() => validateReceipt(JSON.stringify({ ...receipt, ...patch }), identity, operation))
  }
})
test('rejects duplicate, unknown, noncanonical and oversized JSON', () => {
  for (const value of [
    JSON.stringify({ ...receipt, extra: true }),
    JSON.stringify(receipt).replace('"processId":123', '"processId":123,"processId":123'),
    ` ${JSON.stringify(receipt)}`, 'x'.repeat(8193),
  ]) assert.throws(() => validateReceipt(value, identity, operation))
})
