/**
 * CVE-2026-111497 detection vector (Node official regression stream).
 * Not an RCE exploit — discriminates patched vs vulnerable decoders.
 */
import zlib from 'node:zlib';

const VECTOR_HEX =
  '200010414141fcffff07002228f00b60f7f41f000000';
const vector = Buffer.from(VECTOR_HEX, 'hex');

function trySync(label) {
  try {
    const out = zlib.brotliDecompressSync(vector);
    return { label, mode: 'sync', ok: true, outLen: out.length };
  } catch (e) {
    return {
      label,
      mode: 'sync',
      ok: false,
      code: e.code,
      errno: e.errno,
      message: e.message,
    };
  }
}

function tryStream(label) {
  return new Promise((resolve) => {
    const d = zlib.createBrotliDecompress();
    const chunks = [];
    let err;
    d.on('data', (c) => chunks.push(c));
    let settled = false;
    const finish = (payload) => {
      if (settled) return;
      settled = true;
      resolve(payload);
    };
    d.on('error', (e) => {
      finish({
        label,
        mode: 'stream-byte-at-a-time',
        ok: false,
        code: e.code,
        errno: e.errno,
        message: e.message,
      });
    });
    d.on('end', () => {
      if (err) return;
      finish({
        label,
        mode: 'stream-byte-at-a-time',
        ok: true,
        outLen: Buffer.concat(chunks).length,
      });
    });
    for (const byte of vector) {
      d.write(Buffer.from([byte]));
    }
    d.end();
  });
}

async function main() {
  const sync = trySync('official-vector');
  const stream = await tryStream('official-vector');
  console.log(
    JSON.stringify(
      {
        nodeVersion: process.version,
        vectorBytes: vector.length,
        sync,
        stream,
        patchedMarker: zlib.constants?.BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH,
      },
      null,
      2,
    ),
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
