// One TLS handshake against an endpoint, reported as data. Two questions:
// what does the server negotiate, is its certificate valid for the name and
// until when (Node's TLS); and does it still accept TLS 1.0 or 1.1. The second
// is asked on the wire, with a ClientHello written here: current OpenSSL
// builds -- the CI image's among them -- cannot offer the old protocols at all,
// and a test that cannot be made would be no test.
//
// Only the server's first answer is read: a ServerHello in TLS 1.0/1.1 means
// accepted; an alert, a ServerHello in a newer version or a closed connection
// means refused; a timeout or no connection is untested -- never passed.

import net from "node:net";
import tls from "node:tls";

const connect = (host, port, options, timeout) =>
  new Promise((resolve) => {
    // A name goes into SNI; an address may not (RFC 6066).
    const socket = tls.connect({ host, port, ...(!net.isIP(host) && { servername: host }), ...options });
    const done = (value) => {
      socket.destroy();
      resolve(value);
    };
    socket.setTimeout(timeout, () => done({ error: "timeout" }));
    socket.once("secureConnect", () => {
      const cert = socket.getPeerCertificate();
      done({
        protocol: socket.getProtocol(),
        cipher: socket.getCipher()?.name ?? "",
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : "",
        validTo: cert?.valid_to ? new Date(cert.valid_to).toISOString() : "",
      });
    });
    socket.once("error", (e) => done({ error: e.code || e.message }));
  });

// A TLS 1.1 ClientHello (record version 1.0, as clients send it) with SNI and
// the CBC suites every TLS 1.0/1.1 server has: ECDHE and RSA key exchange with
// AES-128/256-SHA, and 3DES as the last resort.
const SUITES = [0xc013, 0xc014, 0xc009, 0xc00a, 0x002f, 0x0035, 0x000a];
export const legacyHello = (host) => {
  const name = Buffer.from(host, "ascii");
  const sni = net.isIP(host) ? Buffer.alloc(0) : Buffer.concat([u16(0x0000), u16(name.length + 5), u16(name.length + 3), Buffer.from([0]), u16(name.length), name]);
  const groups = Buffer.concat([u16(0x000a), u16(8), u16(6), u16(0x0017), u16(0x0018), u16(0x001d)]);
  const points = Buffer.concat([u16(0x000b), u16(2), Buffer.from([1, 0])]);
  const ext = Buffer.concat([sni, groups, points]);
  const suites = Buffer.concat(SUITES.map(u16));
  const body = Buffer.concat([
    u16(0x0302), // TLS 1.1
    Buffer.alloc(32, 0x5a), // client random: no secret is ever derived from it
    Buffer.from([0]), // no session id
    u16(suites.length),
    suites,
    Buffer.from([1, 0]), // compression: null
    u16(ext.length),
    ext,
  ]);
  const hs = Buffer.concat([Buffer.from([1]), u24(body.length), body]);
  return Buffer.concat([Buffer.from([0x16]), u16(0x0301), u16(hs.length), hs]);
};
function u16(n) {
  return Buffer.from([(n >> 8) & 255, n & 255]);
}
function u24(n) {
  return Buffer.from([(n >> 16) & 255, (n >> 8) & 255, n & 255]);
}
// The answer to it: [outcome, detail].
export const legacyAnswer = (buf) => {
  if (buf.length < 5) return ["refused", "connection closed"];
  if (buf[0] === 0x15) return ["refused", `alert ${buf[6] ?? "?"}`];
  if (buf[0] === 0x16 && buf.length >= 11 && buf[5] === 2) {
    const v = buf.readUInt16BE(9);
    return v <= 0x0302 ? [`accepted TLSv1${v === 0x0302 ? ".1" : ""}`, ""] : ["refused", `answered in 0x${v.toString(16)}`];
  }
  return ["refused", `unexpected record ${buf[0]}`];
};
const legacy = (host, port, timeout) =>
  new Promise((resolve) => {
    const socket = net.connect({ host, port });
    let got = Buffer.alloc(0);
    const done = (outcome, detail) => {
      socket.destroy();
      resolve({ legacy: outcome, legacyError: detail });
    };
    socket.setTimeout(timeout, () => (got.length ? done(...legacyAnswer(got)) : done("untested", "timeout")));
    socket.once("connect", () => socket.write(legacyHello(host)));
    socket.on("data", (d) => {
      got = Buffer.concat([got, d]);
      if (got.length >= 11 || got[0] === 0x15) done(...legacyAnswer(got));
    });
    socket.once("end", () => done(...legacyAnswer(got)));
    socket.once("error", (e) => (e.code === "ECONNRESET" ? done("refused", "reset") : done("untested", e.code || e.message)));
  });

export const probe = async (host, port = 443, { timeout = 10000 } = {}) => {
  const current = await connect(host, port, { rejectUnauthorized: false }, timeout);
  return { ...current, ...(await legacy(host, port, timeout)) };
};
