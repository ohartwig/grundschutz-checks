// The TLS 1.0/1.1 probe on the wire, against local servers that answer the way
// real ones do: a protocol_version alert, a ServerHello in TLS 1.1, one in
// TLS 1.2, a reset, silence.
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { legacyAnswer, legacyHello, probe } from "../lib/tls.mjs";

const serve = (answer) =>
  new Promise((resolve) => {
    const server = net.createServer((sock) => sock.once("data", () => answer(sock)));
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
const hello = (v) => Buffer.from([0x16, 0x03, 0x01, 0x00, 0x40, 0x02, 0x00, 0x00, 0x3c, v >> 8, v & 255]);

test("the ClientHello is one well-formed TLS 1.1 handshake record with the name", () => {
  const h = legacyHello("www.example.org");
  assert.equal(h[0], 0x16);
  assert.equal(h.readUInt16BE(3), h.length - 5);
  assert.equal(h[5], 1);
  assert.equal(h.readUIntBE(6, 3), h.length - 9);
  assert.equal(h.readUInt16BE(9), 0x0302);
  assert.ok(h.includes(Buffer.from("www.example.org")));
  assert.ok(!legacyHello("127.0.0.1").includes(Buffer.from("127.0.0.1")), "no SNI for an address");
});

test("the server's first answer decides", () => {
  assert.deepEqual(legacyAnswer(Buffer.from([0x15, 3, 1, 0, 2, 2, 70])), ["refused", "alert 70"]);
  assert.deepEqual(legacyAnswer(hello(0x0302)), ["accepted TLSv1.1", ""]);
  assert.deepEqual(legacyAnswer(hello(0x0301)), ["accepted TLSv1", ""]);
  assert.deepEqual(legacyAnswer(hello(0x0303)), ["refused", "answered in 0x303"]);
  assert.deepEqual(legacyAnswer(Buffer.alloc(0)), ["refused", "connection closed"]);
});

test("on the wire: alert, old hello, reset; silence is untested, not passed", async (t) => {
  const cases = [
    [(s) => s.end(Buffer.from([0x15, 3, 1, 0, 2, 2, 70])), "refused"],
    [(s) => s.end(hello(0x0302)), "accepted TLSv1.1"],
    [(s) => s.resetAndDestroy(), "refused"],
    [() => {}, "untested"],
  ];
  for (const [answer, want] of cases) {
    const server = await serve(answer);
    t.after(() => server.close());
    const r = await probe("127.0.0.1", server.address().port, { timeout: 300 });
    assert.equal(r.legacy, want);
  }
});
