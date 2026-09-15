import { createHash, timingSafeEqual } from 'node:crypto';
import { open, lstat, realpath } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { TextDecoder } from 'node:util';

const MAX_CREDENTIAL_BYTES = 1024 * 1024;
const REFERENCE_NAME = 'DEEPSEEK_API_KEY';

function parseArguments(argv) {
  if (argv.length !== 6) {
    throw new Error('invalid arguments');
  }

  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!['--credentials-path', '--runtime-directory', '--expected-value-sha256'].includes(name) ||
        values.has(name) || typeof value !== 'string' || value.length < 1 || value.length > 4096) {
      throw new Error('invalid arguments');
    }
    values.set(name, value);
  }

  const expectedValueSha256 = values.get('--expected-value-sha256');
  if (!/^[0-9a-f]{64}$/.test(expectedValueSha256 ?? '')) {
    throw new Error('invalid digest');
  }

  return {
    credentialsPath: values.get('--credentials-path'),
    runtimeDirectory: values.get('--runtime-directory'),
    expectedValueSha256,
  };
}

function equalWindowsPath(left, right) {
  return left.toUpperCase() === right.toUpperCase();
}

async function requireExistingPath(path, directory) {
  if (typeof path !== 'string' || !isAbsolute(path)) {
    throw new Error('invalid path');
  }

  const normalized = resolve(path);
  const item = await lstat(normalized);
  if (item.isSymbolicLink() || (directory ? !item.isDirectory() : !item.isFile())) {
    throw new Error('invalid path type');
  }
  const canonical = await realpath(normalized);
  if (!equalWindowsPath(canonical, normalized)) {
    throw new Error('linked path');
  }
  return normalized;
}

async function verify() {
  const args = parseArguments(process.argv.slice(2));
  const runtimeDirectory = await requireExistingPath(args.runtimeDirectory, true);
  const credentialsPath = await requireExistingPath(args.credentialsPath, false);
  const runtimeNode = await requireExistingPath(join(runtimeDirectory, 'node.exe'), false);
  if (!equalWindowsPath(resolve(process.execPath), runtimeNode)) {
    throw new Error('wrong runtime');
  }

  const parserPath = await requireExistingPath(join(
    runtimeDirectory,
    'node_modules',
    '@deepseek-ai',
    'dsh-credentials-local',
    'lib',
    'index.js'), false);

  let documentBytes;
  let valueBytes;
  let observedDigest;
  let expectedDigest;
  let handle;
  try {
    handle = await open(credentialsPath, 'r');
    const before = await handle.stat();
    if (!before.isFile() || before.size < 1 || before.size > MAX_CREDENTIAL_BYTES) {
      throw new Error('invalid credential file');
    }
    documentBytes = await handle.readFile();
    const after = await handle.stat();
    if (documentBytes.length !== before.size || after.size !== before.size) {
      throw new Error('credential file changed');
    }

    const text = new TextDecoder('utf-8', { fatal: true }).decode(documentBytes);
    const parserModule = await import(pathToFileURL(parserPath).href);
    if (typeof parserModule.parseCredentialsDocument !== 'function') {
      throw new Error('missing parser');
    }
    const parsed = parserModule.parseCredentialsDocument(text, 'synthetic-credential.yaml');
    if (!(parsed?.refs instanceof Map) || !(parsed?.records instanceof Map) ||
        !parsed.refs.has(REFERENCE_NAME)) {
      throw new Error('missing reference');
    }

    const value = parsed.refs.get(REFERENCE_NAME);
    if (typeof value !== 'string' || value.length < 1 || value.length > MAX_CREDENTIAL_BYTES) {
      throw new Error('invalid reference');
    }
    valueBytes = Buffer.from(value, 'utf8');
    observedDigest = createHash('sha256').update(valueBytes).digest();
    expectedDigest = Buffer.from(args.expectedValueSha256, 'hex');
    if (expectedDigest.length !== observedDigest.length ||
        !timingSafeEqual(observedDigest, expectedDigest)) {
      throw new Error('reference mismatch');
    }
  } finally {
    await handle?.close();
    documentBytes?.fill(0);
    valueBytes?.fill(0);
    observedDigest?.fill(0);
    expectedDigest?.fill(0);
  }
}

let passed = false;
try {
  await verify();
  passed = true;
} catch {
  passed = false;
}

process.stdout.write(passed ? 'PASS\n' : 'FAIL\n');
process.exitCode = passed ? 0 : 1;
