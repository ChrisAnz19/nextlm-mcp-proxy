const SUPABASE_MCP_URL = "https://wlraonpolaioetvfooeo.supabase.co/functions/v1/mcp-server";
const LOGIN_PAGE_URL = "https://chrisanz19.github.io/nextlm-mcp-login/";

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response("ok", {
        headers: corsHeaders(),
      });
    }

    // RFC 8414: /.well-known/oauth-authorization-server (with optional path suffix)
    if (request.method === "GET" && path.startsWith("/.well-known/oauth-authorization-server")) {
      const metadata = {
        issuer: url.origin,
        authorization_endpoint: LOGIN_PAGE_URL,
        token_endpoint: `${url.origin}/token`,
        registration_endpoint: `${url.origin}/register`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"],
        scopes_supported: ["mcp"],
      };
      return jsonResponse(metadata);
    }

    // RFC 9728: /.well-known/oauth-protected-resource (with optional path suffix)
    if (request.method === "GET" && path.startsWith("/.well-known/oauth-protected-resource")) {
      const metadata = {
        resource: url.origin,
        authorization_servers: [url.origin],
        bearer_methods_supported: ["header"],
        scopes_supported: ["mcp"],
      };
      return jsonResponse(metadata);
    }

    // GET /authorize -> redirect to login page
    if (request.method === "GET" && path === "/authorize") {
      const loginParams = new URLSearchParams();
      for (const key of ["client_id", "redirect_uri", "code_challenge", "code_challenge_method", "state", "scope", "response_type"]) {
        const val = url.searchParams.get(key);
        if (val) loginParams.set(key, val);
      }
      // Pass the proxy origin so the login page POSTs to the right place
      loginParams.set("server_url", url.origin);
      return new Response(null, {
        status: 302,
        headers: { ...corsHeaders(), Location: `${LOGIN_PAGE_URL}?${loginParams.toString()}` },
      });
    }

    // Proxy everything else to Supabase Edge Function
    const supabaseUrl = new URL(SUPABASE_MCP_URL + path);
    supabaseUrl.search = url.search;

    const proxyHeaders = new Headers(request.headers);
    // Don't forward host header
    proxyHeaders.delete("host");

    const proxyRequest = new Request(supabaseUrl.toString(), {
      method: request.method,
      headers: proxyHeaders,
      body: request.method !== "GET" && request.method !== "HEAD" ? request.body : undefined,
    });

    const response = await fetch(proxyRequest);

    // Clone response and add CORS + fix WWW-Authenticate to use our origin
    const newHeaders = new Headers(response.headers);
    Object.entries(corsHeaders()).forEach(([k, v]) => newHeaders.set(k, v));

    // Rewrite WWW-Authenticate to point to our proxy's well-known URL
    const wwwAuth = newHeaders.get("www-authenticate");
    if (wwwAuth && wwwAuth.includes("resource_metadata")) {
      newHeaders.set(
        "www-authenticate",
        `Bearer resource_metadata="${url.origin}/.well-known/oauth-protected-resource"`
      );
    }

    return new Response(response.body, {
      status: response.status,
      headers: newHeaders,
    });
  },
};

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, mcp-session-id",
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS, DELETE",
    "Access-Control-Expose-Headers": "Mcp-Session-Id",
  };
}

function jsonResponse(data) {
  return new Response(JSON.stringify(data), {
    headers: {
      ...corsHeaders(),
      "Content-Type": "application/json",
    },
  });
}
