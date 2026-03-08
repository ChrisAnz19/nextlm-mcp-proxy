import express from "express";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3001;

const SUPABASE_MCP = "https://wlraonpolaioetvfooeo.supabase.co/functions/v1/mcp-server";
const LOGIN_PAGE = readFileSync(join(__dirname, "login.html"), "utf-8");

// ---------- CORS ----------
app.use((req, res, next) => {
  res.set({
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, mcp-session-id",
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS, DELETE",
    "Access-Control-Expose-Headers": "Mcp-Session-Id",
  });
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

// ---------- RFC 9728: Protected Resource Metadata ----------
app.get("/.well-known/oauth-protected-resource*", (req, res) => {
  const origin = `${req.protocol}://${req.get("host")}`;
  res.json({
    resource: origin,
    authorization_servers: [origin],
    bearer_methods_supported: ["header"],
    scopes_supported: ["mcp"],
  });
});

// ---------- RFC 8414: Authorization Server Metadata ----------
app.get("/.well-known/oauth-authorization-server*", (req, res) => {
  const origin = `${req.protocol}://${req.get("host")}`;
  res.json({
    issuer: origin,
    authorization_endpoint: `${origin}/authorize`,
    token_endpoint: `${origin}/token`,
    registration_endpoint: `${origin}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: ["mcp"],
  });
});

// ---------- GET /authorize -> Login Page ----------
app.get("/authorize", (req, res) => {
  const origin = `${req.protocol}://${req.get("host")}`;
  // Inject the proxy origin into the login page
  const html = LOGIN_PAGE.replace("__SERVER_URL__", origin);
  res.type("html").send(html);
});

// ---------- Proxy everything else to Supabase ----------
app.all("*", async (req, res) => {
  const origin = `${req.protocol}://${req.get("host")}`;
  const targetUrl = SUPABASE_MCP + req.path + (req._parsedUrl.search || "");

  // Build headers, forward Authorization
  const headers = { "Content-Type": req.get("content-type") || "application/json" };
  if (req.get("authorization")) headers["Authorization"] = req.get("authorization");
  if (req.get("mcp-session-id")) headers["Mcp-Session-Id"] = req.get("mcp-session-id");

  try {
    const fetchOpts = { method: req.method, headers };
    if (req.method !== "GET" && req.method !== "HEAD") {
      // Read raw body
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      fetchOpts.body = Buffer.concat(chunks);
    }

    const upstream = await fetch(targetUrl, fetchOpts);
    const body = await upstream.text();

    // Copy status and key headers
    res.status(upstream.status);
    const ct = upstream.headers.get("content-type");
    if (ct) res.set("Content-Type", ct);
    const sid = upstream.headers.get("mcp-session-id");
    if (sid) res.set("Mcp-Session-Id", sid);

    // Rewrite WWW-Authenticate to point to our proxy
    const wwwAuth = upstream.headers.get("www-authenticate");
    if (wwwAuth) {
      res.set(
        "WWW-Authenticate",
        `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource"`
      );
    }

    res.send(body);
  } catch (err) {
    console.error("Proxy error:", err.message);
    res.status(502).json({ error: "Proxy error", message: err.message });
  }
});

app.listen(PORT, () => console.log(`MCP proxy listening on :${PORT}`));
