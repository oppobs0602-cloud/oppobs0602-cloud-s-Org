import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes, scrypt, createHash, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const DATA_FILE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../.data/db.json");
const blobStores = new Map();

function loadDisk() {
  try {
    if (!existsSync(DATA_FILE)) return;
    const raw = JSON.parse(readFileSync(DATA_FILE, "utf8"));
    if (!raw || typeof raw !== "object") return;
    const now = Date.now();
    for (const [storeName, entries] of Object.entries(raw)) {
      if (!entries || typeof entries !== "object") continue;
      const m = new Map();
      for (const [k, v] of Object.entries(entries)) {
        if (typeof v !== "string") continue;
        if (storeName === "sessions") {
          try {
            const s = JSON.parse(v);
            if (!s || s.exp <= now) continue;
          } catch { continue; }
        }
        m.set(k, v);
      }
      blobStores.set(storeName, m);
    }
  } catch (err) {
    console.error("Failed to load persisted store:", err);
  }
}

function saveDisk() {
  try {
    mkdirSync(path.dirname(DATA_FILE), { recursive: true });
    const now = Date.now();
    const out = {};
    for (const [storeName, m] of blobStores.entries()) {
      const obj = {};
      for (const [k, v] of m.entries()) {
        if (storeName === "sessions") {
          try {
            const s = JSON.parse(v);
            if (!s || s.exp <= now) { m.delete(k); continue; }
          } catch { m.delete(k); continue; }
        } else if (storeName === "limits") {
          try {
            const r = JSON.parse(v);
            if (r && r.until && r.until <= now) { m.delete(k); continue; }
          } catch { m.delete(k); continue; }
        }
        obj[k] = v;
      }
      out[storeName] = obj;
    }
    const tmp = DATA_FILE + ".tmp";
    writeFileSync(tmp, JSON.stringify(out), "utf8");
    renameSync(tmp, DATA_FILE);
  } catch (err) {
    console.error("Failed to persist store:", err);
  }
}

loadDisk();

function getStore({ name }) {
  if (!blobStores.has(name)) blobStores.set(name, new Map());
  const store = blobStores.get(name);
  return {
    async get(key, opts) {
      if (!store.has(key)) return null;
      const val = store.get(key);
      return opts?.type === "json" ? JSON.parse(val) : val;
    },
    async setJSON(key, value) {
      store.set(key, JSON.stringify(value));
      saveDisk();
    },
    async delete(key) {
      if (store.delete(key)) saveDisk();
    },
    async list() {
      return { blobs: Array.from(store.keys(), (key) => ({ key })) };
    },
  };
}

const scryptP = promisify(scrypt);
const NAME = /^[\p{L}\p{M}\p{N}_]{3,14}$/u;
const COLS = {
  lb: { order: ["wave"] },
  rank: { order: ["rp"] },
  saves: { order: [] },
};
const MAX_ROWS = 300;
const SESSION_S = 30 * 24 * 3600;
const DUMMY = randomBytes(16);
const cache = new Map();

const cheatOk = (name) => {
  let v = "";
  try { v = (globalThis.Netlify && Netlify.env.get("CHEAT_USERS")) || process.env.CHEAT_USERS || ""; } catch { v = process.env.CHEAT_USERS || ""; }
  return v.toLowerCase().split(",").map((x) => x.trim()).filter(Boolean).includes(String(name).toLowerCase());
};

const sha = (s) => createHash("sha256").update(s).digest("hex");
const st = (n) => getStore({ name: n, consistency: "strong" });
const json = (o, status = 200, headers = {}) =>
  new Response(JSON.stringify(o), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...headers },
  });
const isHttps = (req) =>
  new URL(req.url).protocol === "https:" ||
  (req.headers.get("x-forwarded-proto") || "").split(",")[0].trim() === "https";
const cookie = (v, age, https = true) =>
  `sid=${v}; Path=/; HttpOnly; ${https ? "Secure; SameSite=None; Partitioned" : "SameSite=Lax"}; Max-Age=${age}`;
const isJson = (req) => (req.headers.get("content-type") || "").includes("application/json");
const sameOrigin = (req) => {
  if ((req.headers.get("x-requested-with") || "").toLowerCase() === "xmlhttprequest") return true;
  const origin = req.headers.get("origin");
  if (!origin) return false;
  try {
    const oHost = new URL(origin).host.toLowerCase();
    const host = (req.headers.get("x-forwarded-host") || req.headers.get("host") || "").split(",")[0].trim().toLowerCase();
    return !!host && oHost === host;
  } catch {
    return false;
  }
};
const int = (v, lo, hi) => {
  v = Math.floor(Number(v));
  return Number.isFinite(v) ? Math.min(hi, Math.max(lo, v)) : lo;
};
const sidOf = (req) => {
  const authH = req.headers.get("authorization") || "";
  const m = /^Bearer\s+([a-f0-9]{64})$/i.exec(authH.trim());
  if (m) return m[1];
  return (/(?:^|;\s*)sid=([a-f0-9]{64})/.exec(req.headers.get("cookie") || "") || [])[1];
};
const hashPw = async (pw, salt) => (await scryptP(pw.normalize("NFKC"), salt, 64)).toString("hex");

async function getSession(req) {
  const t = sidOf(req);
  if (!t) return null;
  const s = await st("sessions").get(sha(t), { type: "json" });
  return s && s.exp > Date.now() ? s : null;
}

async function lockLeft(key) {
  const r = await st("limits").get(key, { type: "json" });
  return r && r.until > Date.now() ? r.until - Date.now() : 0;
}
async function addFail(key, max, lockMs) {
  const L = st("limits");
  const r = (await L.get(key, { type: "json" })) || { n: 0 };
  const n = (r.until && r.until <= Date.now() ? 0 : r.n || 0) + 1;
  await L.setJSON(key, n >= max ? { n: 0, until: Date.now() + lockMs } : { n });
}

async function auth(req, ctx) {
  if (req.method === "GET") {
    const s = await getSession(req);
    return json({ user: s ? { id: s.uid, name: s.name } : null });
  }
  if (req.method !== "POST") return json({ error: "method" }, 405);
  if (!sameOrigin(req)) return json({ error: "forbidden" }, 403);
  if (!isJson(req)) return json({ error: "bad request" }, 400);
  let b;
  try { b = await req.json(); } catch { return json({ error: "bad request" }, 400); }

  if (b.a === "logout") {
    const t = sidOf(req);
    if (t) await st("sessions").delete(sha(t));
    return json({ ok: true }, 200, { "set-cookie": cookie("", 0, isHttps(req)) });
  }
  if (b.a === "cheat") {
    const s = await getSession(req);
    return json({ ok: !!s && cheatOk(s.name) });
  }
  if (b.a !== "register" && b.a !== "login") return json({ error: "bad request" }, 400);

  const name = String(b.name ?? "").normalize("NFC").trim();
  const pw = String(b.pw ?? "");
  if (!NAME.test(name)) return json({ error: "ชื่อต้องยาว 3-14 ตัว ใช้ได้เฉพาะตัวอักษร ตัวเลข และ _" }, 400);
  if (pw.length < 6 || pw.length > 100) return json({ error: "รหัสผ่านต้องยาว 6-100 ตัว" }, 400);

  const key = "u_" + sha(name.toLowerCase());
  const users = st("users");

  const issue = async (rec) => {
    const token = randomBytes(32).toString("hex");
    await st("sessions").setJSON(sha(token), { uid: rec.id, name: rec.name, exp: Date.now() + SESSION_S * 1000 });
    return json({ user: { id: rec.id, name: rec.name }, token }, 200, { "set-cookie": cookie(token, SESSION_S, isHttps(req)) });
  };

  if (b.a === "register") {
    const ip = (ctx && ctx.ip) || req.headers.get("x-nf-client-connection-ip") || "";
    const rk = ip ? "reg_" + sha(ip) : "";
    if (rk && (await lockLeft(rk))) return json({ error: "สมัครบ่อยเกินไป ลองใหม่ภายหลัง" }, 429);
    if (await users.get(key, { type: "json" })) return json({ error: "ชื่อนี้ถูกใช้แล้ว" }, 409);
    const salt = randomBytes(16);
    const rec = { id: "u" + randomBytes(12).toString("hex"), name, salt: salt.toString("hex"), hash: await hashPw(pw, salt), created: Date.now() };
    await users.setJSON(key, rec);
    if (rk) await addFail(rk, 10, 3600000);
    return issue(rec);
  }

  const lk = "l_" + key;
  const w = await lockLeft(lk);
  if (w) return json({ error: "ลองผิดหลายครั้ง กรุณารอ " + Math.ceil(w / 60000) + " นาที" }, 429);
  const rec = await users.get(key, { type: "json" });
  const h = Buffer.from(await hashPw(pw, rec ? Buffer.from(rec.salt, "hex") : DUMMY), "hex");
  const ok = rec && timingSafeEqual(h, Buffer.from(rec.hash, "hex"));
  if (!ok) {
    await addFail(lk, 8, 300000);
    return json({ error: "ชื่อหรือรหัสผ่านไม่ถูกต้อง" }, 401);
  }
  await st("limits").delete(lk);
  return issue(rec);
}

function clean(col, d, name) {
  if (!d || typeof d !== "object") return null;
  if (col === "lb") return { name, wave: int(d.wave, 0, 9999), lv: int(d.lv, 0, 999), t: Date.now() };
  if (col === "rank") {
    const def = d.def;
    if (def !== undefined && (!Array.isArray(def) || JSON.stringify(def).length > 20000)) return null;
    return { name, rp: int(d.rp, 0, 99999), def: def || [], t: Date.now() };
  }
  if (col === "saves") {
    const s = String(d.s ?? "");
    return s.length > 400000 ? null : { s };
  }
  return null;
}

async function db(req) {
  if (req.method === "PUT") {
    if (!sameOrigin(req)) return json({ error: "forbidden" }, 403);
    if (!isJson(req)) return json({ error: "bad request" }, 400);
    const s = await getSession(req);
    if (!s) return json({ error: "login" }, 401);
    let b;
    try { b = await req.json(); } catch { return json({ error: "bad request" }, 400); }
    if (!COLS[b.col]) return json({ error: "bad request" }, 400);
    if (b.id !== s.uid) return json({ error: "forbidden" }, 403);
    const data = clean(b.col, b.data, s.name);
    if (!data) return json({ error: "bad data" }, 400);
    await st("game-" + b.col).setJSON(b.id, data);
    cache.delete(b.col);
    return json({ ok: true });
  }

  if (req.method !== "GET") return json({ error: "method" }, 405);
  const u = new URL(req.url);
  const col = u.searchParams.get("col");
  if (!COLS[col]) return json({ error: "bad request" }, 400);
  const store = st("game-" + col);

  const id = u.searchParams.get("id");
  if (id) {
    const s = await getSession(req);
    if (!s) return json({ error: "login" }, 401);
    if (col !== "saves" || id !== s.uid) return json({ error: "forbidden" }, 403);
    const data = await store.get(id, { type: "json" });
    return json(data ? { exists: true, data } : { exists: false });
  }

  const order = u.searchParams.get("order");
  if (!COLS[col].order.includes(order)) return json({ error: "bad order" }, 400);
  const limit = int(u.searchParams.get("limit") || 50, 1, 100);

  let c = cache.get(col);
  if (!c || Date.now() - c.t > 5000) {
    const { blobs } = await store.list();
    const rows = (
      await Promise.all(
        blobs.slice(0, MAX_ROWS).map(async (x) => {
          const d = await store.get(x.key, { type: "json" });
          return d ? { id: x.key, ...d } : null;
        })
      )
    ).filter(Boolean);
    c = { t: Date.now(), rows };
    cache.set(col, c);
  }
  const docs = [...c.rows].sort((a, b) => (b[order] ?? 0) - (a[order] ?? 0)).slice(0, limit);
  return json({ docs });
}

export default async (req, ctx) => {
  try {
    return new URL(req.url).pathname === "/api/auth" ? await auth(req, ctx) : await db(req);
  } catch (e) {
    return json({ error: "server" }, 500);
  }
};

export const config = { path: ["/api/db", "/api/auth"] };
