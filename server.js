import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";
import dbHandler from "./netlify/functions/db.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = 3000;

app.set("trust proxy", 1);

app.all(["/api/db", "/api/auth"], express.raw({ type: "*/*", limit: "1mb" }), async (req, res) => {
  try {
    const proto = (req.headers["x-forwarded-proto"] || req.protocol || "http").split(",")[0].trim();
    const host = req.headers.host || `localhost:${PORT}`;
    const url = `${proto}://${host}${req.originalUrl}`;

    const headers = new Headers();
    for (const [key, val] of Object.entries(req.headers)) {
      if (Array.isArray(val)) {
        for (const item of val) headers.append(key, item);
      } else if (val !== undefined) {
        headers.set(key, val);
      }
    }

    const init = { method: req.method, headers };
    if (req.method !== "GET" && req.method !== "HEAD" && Buffer.isBuffer(req.body) && req.body.length > 0) {
      init.body = req.body;
    }

    const webRes = await dbHandler(new Request(url, init), { ip: req.ip });
    res.status(webRes.status);

    if (typeof webRes.headers.getSetCookie === "function") {
      for (const cookieVal of webRes.headers.getSetCookie()) {
        res.append("set-cookie", cookieVal);
      }
    }
    webRes.headers.forEach((value, key) => {
      if (key.toLowerCase() !== "set-cookie") {
        res.setHeader(key, value);
      }
    });

    const buf = Buffer.from(await webRes.arrayBuffer());
    res.send(buf);
  } catch (err) {
    console.error("API handler error:", err);
    res.status(500).json({ error: "server" });
  }
});

import fs from "node:fs";

const fbConfigPath = path.join(__dirname, "firebase-applet-config.json");
const readFbConfigJson = () => {
  try {
    return JSON.parse(fs.readFileSync(fbConfigPath, "utf8"));
  } catch {
    return null;
  }
};

app.get("/firebase-applet-config.json", (_req, res) => {
  res.sendFile(fbConfigPath);
});

app.get(["/", "/index.html"], (_req, res) => {
  try {
    let html = fs.readFileSync(path.join(__dirname, "index.html"), "utf8");
    const cfg = readFbConfigJson();
    if (cfg) {
      const safeJson = JSON.stringify(cfg).replace(/</g, "\\u003c");
      html = html.replace("<!--__FB_CFG__-->", `<script>window.__FB_CONFIG=${safeJson};</script>`);
    }
    res.type("html").send(html);
  } catch (err) {
    console.error("Failed to serve index.html:", err);
    res.sendFile(path.join(__dirname, "index.html"));
  }
});

app.get("/favicon.ico", (_req, res) => {
  res.sendFile(path.join(__dirname, "favicon.ico"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server listening on http://0.0.0.0:${PORT}`);
});
