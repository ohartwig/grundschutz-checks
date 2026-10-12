// One TLS handshake against an endpoint, reported as data. Two kinds of
// handshake are made: the normal one (what does the server negotiate, is its
// certificate valid for the name, when does it expire), and one that offers
// only TLS 1.0 and 1.1 (does the server still accept them).
//
// A handshake the client itself cannot offer -- OpenSSL built without the old
// protocols -- is reported as such, not as a refusal by the server: a test
// that could not be made has not been passed.

import tls from "node:tls";

const connect = (host, port, options, timeout) =>
  new Promise((resolve) => {
    const socket = tls.connect({ host, port, servername: host, ...options });
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

// How the old handshake ended. A TLS error from the exchange (a
// protocol_version alert, a reply in a newer version than offered) or a reset
// is the server refusing; that this client cannot offer the protocol at all,
// a timeout or no connection is no answer either way.
const legacyOutcome = (r) => {
  if (!r.error) return `accepted ${r.protocol}`;
  if (r.error === "ERR_SSL_NO_PROTOCOLS_AVAILABLE") return "untested";
  if (r.error.startsWith("ERR_SSL_") || r.error === "ECONNRESET") return "refused";
  return "untested";
};

export const probe = async (host, port = 443, { timeout = 10000 } = {}) => {
  const current = await connect(host, port, { rejectUnauthorized: false }, timeout);
  const legacy = await connect(
    host,
    port,
    { rejectUnauthorized: false, minVersion: "TLSv1", maxVersion: "TLSv1.1", ciphers: "DEFAULT@SECLEVEL=0" },
    timeout,
  );
  return {
    ...current,
    legacy: legacyOutcome(legacy),
    legacyError: legacy.error ?? "",
  };
};
