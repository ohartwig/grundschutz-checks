// Every endpoint named speaks TLS 1.2 or 1.3, refuses TLS 1.0 and 1.1, and
// presents a certificate valid for its name that does not expire within the
// days allowed (default 14) -- the core of the BSI Mindeststandard TLS for a
// server.
//
// Evidences part of KONF.14.1 (transport encryption as required) and of
// KONF.14.1.1 (insecure connections disabled): for the endpoints named, not
// for every connection the application makes.

const CURRENT = ["TLSv1.2", "TLSv1.3"];
const DAY = 864e5;

export default {
  name: "tls-endpoints",
  title: "TLS of public endpoints",
  description:
    "Every endpoint named negotiates TLS 1.2 or 1.3, refuses TLS 1.0 and 1.1, and presents a certificate valid for its name that does not expire within the days allowed (default 14).",
  method: "TEST",
  requirements: ["KONF.14.1", "KONF.14.1.1"],
  partial: ["KONF.14.1", "KONF.14.1.1"],
  subjects: (config) => `The endpoints ${(config.tls?.endpoints ?? []).join(", ") || "(none named)"}.`,
  needs: ["probe"],
  async run({ config, probe, now }) {
    const min = config.tls?.["min-days-valid"] ?? 14;
    const out = [];
    for (const ep of config.tls?.endpoints ?? []) {
      const [host, port = "443"] = ep.split(":");
      const r = await probe(host, Number(port));
      const problems = [];
      if (r.error) problems.push(`no TLS handshake: ${r.error}`);
      else {
        if (!CURRENT.includes(r.protocol)) problems.push(`negotiates ${r.protocol}`);
        if (!r.authorized) problems.push(`certificate not valid: ${r.authorizationError}`);
        const days = Math.floor((Date.parse(r.validTo) - now.getTime()) / DAY);
        if (!(days >= min)) problems.push(`certificate expires in ${days} days`);
      }
      if (r.legacy.startsWith("accepted")) problems.push(`${r.legacy.replace("accepted", "accepts")}`);
      if (r.legacy === "untested") problems.push(`TLS 1.0/1.1 could not be tested (${r.legacyError})`);
      out.push({
        title: ep,
        href: `https://${host}${port === "443" ? "" : `:${port}`}/`,
        satisfied: !problems.length,
        detail: problems.length ? problems.join("; ") : `${r.protocol} ${r.cipher}, TLS 1.0/1.1 refused, certificate valid until ${r.validTo.slice(0, 10)}`,
      });
    }
    return out;
  },
};
