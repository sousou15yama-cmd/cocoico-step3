// ============================================================
// COCOiCO 共通バックエンド Worker
//  - Gemini プロキシ（POST / ：本文をそのまま Gemini へ中継）
//  - 簡易ログイン＆共有DB（KV: env.COCOICO_KV を使用）
//      POST /signup     {username, passcode}        -> {ok, username, token}
//      POST /login      {username, passcode}        -> {ok, username, token}
//      POST /register   {username, token, restaurant}-> {ok}
//      GET  /restaurants                            -> {restaurants:[...]}
//
// 必要な設定（Cloudflare ダッシュボード）:
//   1) KV namespace を作成し、この Worker の Settings → Variables and Secrets →
//      「KV Namespace Bindings」で 変数名 COCOICO_KV にバインド
//   2) Secret 変数 GEMINI_KEY（Gemini APIキー）
//   3) ALLOWED に自分の Pages ドメインを記載（既定で設定済み）
//
// ※ これはデモ用の簡易認証です（レート制限なし・トークン無期限）。
//   機微情報は扱わない前提でご利用ください。
// ============================================================

const ALLOWED = [
  "https://sousou15yama-cmd.github.io",
  "http://localhost:8756",
  "http://localhost:8755",
  "http://127.0.0.1:8756"
];
const SALT = "cocoico_2026_salt_v1";

function corsHeaders(origin) {
  const allow = ALLOWED.includes(origin) ? origin : ALLOWED[0];
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin",
  };
}
function json(obj, status, c) {
  return new Response(JSON.stringify(obj), { status: status || 200, headers: { ...c, "Content-Type": "application/json" } });
}
async function sha256(s) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const c = corsHeaders(origin);
    if (request.method === "OPTIONS") return new Response(null, { headers: c });
    if (origin && !ALLOWED.includes(origin)) return json({ error: "forbidden" }, 403, c);

    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, ""); // 末尾スラッシュ除去
    const KV = env.COCOICO_KV;

    try {
      // ---------- 認証 ----------
      if (path === "/signup" || path === "/login") {
        if (!KV) return json({ error: "KV未設定" }, 500, c);
        const { username, passcode } = await request.json();
        if (!username || !passcode || String(username).length > 20) return json({ error: "入力エラー" }, 400, c);
        const uname = String(username).trim();
        const key = "user:" + uname;
        const existing = await KV.get(key);
        const hash = await sha256(uname + ":" + passcode + ":" + SALT);
        if (path === "/signup") {
          if (existing) return json({ error: "そのユーザー名は使われています" }, 409, c);
          const token = crypto.randomUUID();
          await KV.put(key, JSON.stringify({ username: uname, hash, token, createdAt: Date.now() }));
          return json({ ok: true, username: uname, token }, 200, c);
        } else {
          if (!existing) return json({ error: "ユーザーが見つかりません" }, 404, c);
          const u = JSON.parse(existing);
          if (u.hash !== hash) return json({ error: "パスコードが違います" }, 401, c);
          const token = crypto.randomUUID();
          u.token = token;
          await KV.put(key, JSON.stringify(u));
          return json({ ok: true, username: uname, token }, 200, c);
        }
      }

      // ---------- 店の共有登録 ----------
      if (path === "/register" && request.method === "POST") {
        if (!KV) return json({ error: "KV未設定" }, 500, c);
        const { username, token, restaurant } = await request.json();
        const raw = await KV.get("user:" + username);
        const u = raw ? JSON.parse(raw) : null;
        if (!u || u.token !== token) return json({ error: "認証エラー（再ログインしてください）" }, 401, c);
        if (!restaurant || !restaurant.name) return json({ error: "店名が必要です" }, 400, c);
        const listRaw = await KV.get("restaurants");
        const list = listRaw ? JSON.parse(listRaw) : [];
        if (!list.some((r) => r.name === restaurant.name)) {
          restaurant.created_by_name = username;
          restaurant.created_at = Date.now();
          list.push(restaurant);
          if (list.length > 2000) list.splice(0, list.length - 2000);
          await KV.put("restaurants", JSON.stringify(list));
        }
        return json({ ok: true }, 200, c);
      }

      // ---------- 共有店の取得 ----------
      if (path === "/restaurants" && request.method === "GET") {
        const raw = KV ? await KV.get("restaurants") : null;
        return json({ restaurants: raw ? JSON.parse(raw) : [] }, 200, c);
      }
    } catch (e) {
      return json({ error: String(e) }, 500, c);
    }

    // ---------- 既定: Gemini プロキシ ----------
    if (request.method !== "POST") return new Response("ok", { headers: c });
    const MODEL = "gemini-2.5-flash-lite"; // 無料枠が広く高速。混雑/レート制限に強い
    const gurl = "https://generativelanguage.googleapis.com/v1beta/models/" + MODEL + ":generateContent?key=" + env.GEMINI_KEY;
    const body = await request.text();
    const r = await fetch(gurl, { method: "POST", headers: { "Content-Type": "application/json" }, body });
    const t = await r.text();
    return new Response(t, { status: r.status, headers: { ...c, "Content-Type": "application/json" } });
  },
};
