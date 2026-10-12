// A small, read-only GitLab API client: what the checks need and nothing more.
// It never writes. A failed request is an error, never an empty answer: a
// check that could not look has not found anything to be as required.

export class ApiError extends Error {}

export const gitlab = ({ url, token, fetch = globalThis.fetch }) => {
  if (!url) throw new ApiError("gitlab.url is not set");
  const base = `${url.replace(/\/+$/, "")}/api/v4`;
  const headers = token ? { "PRIVATE-TOKEN": token } : {};
  const request = async (path) => {
    const res = await fetch(`${base}${path}`, { headers });
    return res;
  };
  // One object. With missing: "null", a 404 is an answer (an unprotected
  // branch has no protection to read); any other failure is an error.
  const get = async (path, { missing = "error" } = {}) => {
    const res = await request(path);
    if (res.status === 404 && missing === "null") return null;
    if (!res.ok) throw new ApiError(`GET ${path}: ${res.status}`);
    return res.json();
  };
  // Every page of a list, following x-next-page.
  const all = async (path) => {
    const out = [];
    const sep = path.includes("?") ? "&" : "?";
    for (let page = "1"; page; ) {
      const res = await request(`${path}${sep}per_page=100&page=${page}`);
      if (!res.ok) throw new ApiError(`GET ${path}: ${res.status}`);
      out.push(...(await res.json()));
      page = res.headers.get("x-next-page") || "";
    }
    return out;
  };
  return { url: url.replace(/\/+$/, ""), get, all };
};

export const enc = (s) => encodeURIComponent(s);

// Whether a project runs CI at all: jobs enabled, and a configuration -- the
// default .gitlab-ci.yml on the default branch, or another path or project
// named in the settings. "Enabled" alone says nothing: a project without a
// configuration never runs a pipeline.
export const hasCi = async (api, path, p) => {
  if (p.builds_access_level === "disabled") return false;
  if (p.ci_config_path) return true;
  if (!p.default_branch) return false;
  const f = await api.get(`/projects/${enc(path)}/repository/files/.gitlab-ci.yml?ref=${enc(p.default_branch)}`, { missing: "null" });
  return Boolean(f);
};

// The projects a check looks at: those named, and every non-archived project
// of the groups named (with subgroups). Sorted, each once. A project listed in
// the check's "accept" -- a deliberate exception, with its reason -- is not
// looked at; the check names it in the evidence, so the exception stays
// visible in every result instead of disappearing from it.
export const projects = async (api, { projects: named = [], groups = [] }, accept = {}, note = () => {}) => {
  const paths = new Set(named);
  for (const g of groups) {
    for (const p of await api.all(`/groups/${enc(g)}/projects?include_subgroups=true&archived=false&with_shared=false`)) {
      paths.add(p.path_with_namespace);
    }
  }
  const taken = [...paths].sort().filter((p) => !(p in accept));
  for (const [p, why] of Object.entries(accept).sort()) if (paths.has(p)) note(`accepted, not looked at: ${p} -- ${why}`);
  return taken;
};
