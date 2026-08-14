/**
 * Bun Voice Agent Starter - Backend Server
 *
 * Simple WebSocket proxy to Deepgram's Voice Agent API.
 * Forwards all messages (JSON and binary) bidirectionally between client and Deepgram.
 *
 * Routes:
 *   GET  /api/session       - Issue JWT session token
 *   GET  /api/metadata      - Project metadata from deepgram.toml
 *   WS   /api/voice-agent   - WebSocket proxy to Deepgram Agent API (auth required)
 */

// ============================================================================
// IMPORTS
// ============================================================================

import crypto from "crypto";
import jwt from "jsonwebtoken";
import TOML from "@iarna/toml";
import { DeepgramClient } from "@deepgram/sdk";

// ============================================================================
// ENV LOADING - Bun loads .env files automatically
// ============================================================================

// No dotenv needed — Bun natively loads .env files on startup.
// Access variables via process.env or Bun.env.

// ============================================================================
// CONFIGURATION - Customize these values for your needs
// ============================================================================

/**
 * Server configuration - These can be overridden via environment variables
 */
interface ServerConfig {
  port: number;
  host: string;
  deepgramApiKey: string;
}

const config: ServerConfig = {
  port: parseInt(process.env.PORT || "8081"),
  host: process.env.HOST || "0.0.0.0",
  deepgramApiKey: loadApiKey(),
};

// ============================================================================
// DEEPGRAM SDK CLIENT
// ============================================================================

// A single SDK client is reused across connections; the API key is resolved
// here so the browser never sees it. The Voice Agent websocket is managed by
// the SDK (auth, framing, reconnection) via `deepgram.agent.v1`.
//
// DEEPGRAM_BASE_URL (e.g. a staging host like wss://agent.staging.deepgram.com)
// overrides the default agent endpoint.
const baseUrl = process.env.DEEPGRAM_BASE_URL;
const deepgram = new DeepgramClient({
  apiKey: config.deepgramApiKey,
  ...(baseUrl
    ? {
        environment: {
          base: baseUrl
            .replace(/^wss:\/\//, "https://")
            .replace(/^ws:\/\//, "http://"),
          production: baseUrl,
          agent: baseUrl,
          agentRest: baseUrl
            .replace(/^wss:\/\//, "https://")
            .replace(/^ws:\/\//, "http://"),
        },
      }
    : {}),
});
if (baseUrl) {
  console.log(`Using custom Deepgram base URL: ${baseUrl}`);
}

// ============================================================================
// SESSION AUTH - JWT tokens for production security
// ============================================================================

/**
 * Session secret for signing JWTs.
 * Auto-generated in development; set SESSION_SECRET env var in production.
 */
const SESSION_SECRET: string =
  process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");

/** JWT expiry time (1 hour) */
const JWT_EXPIRY = "1h";

/**
 * Creates a signed JWT session token
 * @returns Signed JWT string
 */
function createSessionToken(): string {
  return jwt.sign(
    { iat: Math.floor(Date.now() / 1000) },
    SESSION_SECRET,
    { expiresIn: JWT_EXPIRY }
  );
}

/**
 * Validates JWT from WebSocket subprotocol: access_token.<jwt>
 * Returns the full subprotocol string if valid, null if invalid.
 * @param protocols - Raw Sec-WebSocket-Protocol header value
 * @returns The valid subprotocol string, or null
 */
function validateWsToken(protocols: string | null): string | null {
  if (!protocols) return null;
  const list = protocols.split(",").map((s) => s.trim());
  const tokenProto = list.find((p) => p.startsWith("access_token."));
  if (!tokenProto) return null;
  const token = tokenProto.slice("access_token.".length);
  try {
    jwt.verify(token, SESSION_SECRET);
    return tokenProto;
  } catch {
    return null;
  }
}

// ============================================================================
// API KEY LOADING - Load Deepgram API key from .env
// ============================================================================

/**
 * Loads the Deepgram API key from environment variables.
 * Exits with a helpful error message if the key is not found.
 * @returns The Deepgram API key string
 */
function loadApiKey(): string {
  const apiKey = process.env.DEEPGRAM_API_KEY;

  if (!apiKey) {
    console.error("\n ERROR: Deepgram API key not found!\n");
    console.error("Please set your API key using one of these methods:\n");
    console.error("1. Create a .env file (recommended):");
    console.error("   DEEPGRAM_API_KEY=your_api_key_here\n");
    console.error("2. Environment variable:");
    console.error("   export DEEPGRAM_API_KEY=your_api_key_here\n");
    console.error("Get your API key at: https://console.deepgram.com\n");
    process.exit(1);
  }

  return apiKey;
}

// ============================================================================
// HELPER FUNCTIONS - Modular logic for easier understanding and testing
// ============================================================================

/**
 * Returns standard CORS headers for cross-origin requests.
 * Bun has no CORS middleware, so we add these to every response.
 * @returns Headers object with CORS headers
 */
function getCorsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}

/** Reserved WebSocket close codes that cannot be set by applications */
const RESERVED_CLOSE_CODES = [1004, 1005, 1006, 1015];

/**
 * Returns a safe WebSocket close code, translating reserved codes to 1000.
 * The WebSocket spec reserves codes 1004, 1005, 1006, and 1015 —
 * applications must not send these in close frames.
 * @param code - The close code received from the remote peer
 * @returns A safe close code suitable for sending in a close frame
 */
function getSafeCloseCode(code: number | undefined): number {
  if (
    typeof code === "number" &&
    code >= 1000 &&
    code <= 4999 &&
    !RESERVED_CLOSE_CODES.includes(code)
  ) {
    return code;
  }
  return 1000;
}

// ============================================================================
// CONNECTION TRACKING - Track active WebSocket connections for cleanup
// ============================================================================

/** Set of active client WebSocket connections for graceful shutdown */
const activeConnections = new Set<WebSocket>();

// ============================================================================
// SESSION ROUTES - Auth endpoints (unprotected)
// ============================================================================

/**
 * GET /api/session
 * Issues a signed JWT session token.
 * @returns JSON response with { token }
 */
function handleGetSession(): Response {
  const token = createSessionToken();
  return Response.json({ token }, { headers: getCorsHeaders() });
}

/**
 * GET /api/metadata
 * Returns metadata about this starter application from deepgram.toml.
 * Required for standardization compliance.
 * @returns JSON response with the [meta] section from deepgram.toml
 */
async function handleMetadata(): Promise<Response> {
  try {
    const tomlContent = await Bun.file("deepgram.toml").text();
    const parsed = TOML.parse(tomlContent) as Record<string, unknown>;

    if (!parsed.meta) {
      return Response.json(
        {
          error: "INTERNAL_SERVER_ERROR",
          message: "Missing [meta] section in deepgram.toml",
        },
        { status: 500, headers: getCorsHeaders() }
      );
    }

    return Response.json(parsed.meta, { headers: getCorsHeaders() });
  } catch (error) {
    console.error("Error reading metadata:", error);
    return Response.json(
      {
        error: "INTERNAL_SERVER_ERROR",
        message: "Failed to read metadata from deepgram.toml",
      },
      { status: 500, headers: getCorsHeaders() }
    );
  }
}

/**
 * GET /health
 * Simple health check endpoint.
 * @returns JSON response with { status: "ok" }
 */
function handleHealth(): Response {
  return Response.json({ status: "ok" }, { headers: getCorsHeaders() });
}

// ============================================================================
// WEBSOCKET PROXY - Bidirectional proxy to Deepgram Voice Agent API
// ============================================================================

/**
 * WebSocket message and close event handlers for the voice agent proxy.
 * Bun.serve() uses a websocket object with open/message/close/error callbacks.
 * We store the Deepgram upstream WebSocket on the ws.data property.
 */
interface WsData {
  // The SDK Voice Agent connection (agent.v1 socket) for this client.
  dgConn: any;
  // Whether the Deepgram socket is open and ready to receive media/control.
  dgReady: boolean;
  // Browser messages received before Deepgram is ready, flushed on open.
  pending: Array<{ binary: true; data: Uint8Array } | { binary: false; msg: any }>;
}

/**
 * Route a JSON control message from the browser to the matching agent.v1
 * method on the Deepgram connection. The browser protocol is unchanged: the
 * client sends its Settings first, then optional Update / Inject / KeepAlive
 * messages, exactly as before.
 */
function dispatchAgentControl(dgConn: any, msg: any): void {
  try {
    switch (msg?.type) {
      case "Settings":
        dgConn.sendSettings(msg);
        break;
      case "KeepAlive":
        dgConn.sendKeepAlive({ type: "KeepAlive" });
        break;
      case "UpdateSpeak":
        dgConn.sendUpdateSpeak(msg);
        break;
      case "UpdatePrompt":
        dgConn.sendUpdatePrompt(msg);
        break;
      case "UpdateListen":
        dgConn.sendUpdateListen(msg);
        break;
      case "UpdateThink":
        dgConn.sendUpdateThink(msg);
        break;
      case "InjectUserMessage":
        dgConn.sendInjectUserMessage(msg);
        break;
      case "InjectAgentMessage":
        dgConn.sendInjectAgentMessage(msg);
        break;
      case "FunctionCallResponse":
        dgConn.sendFunctionCallResponse(msg);
        break;
      default:
        console.warn("Ignoring unknown client control message type:", msg?.type);
    }
  } catch (error) {
    console.error("Failed to forward control message to Deepgram:", error);
  }
}

/**
 * Establishes a connection to the Deepgram Voice Agent API via the SDK and
 * sets up bidirectional message forwarding. The SDK manages the upstream
 * websocket, auth, and framing; the browser-facing protocol is unchanged.
 * @param clientWs - The Bun server-side WebSocket for the connected client
 */
async function connectToDeepgram(
  clientWs: import("bun").ServerWebSocket<WsData>
): Promise<void> {
  console.log("Initiating Deepgram connection...");

  // Create the agent connection object (not yet connected). Auth is resolved
  // from the API key by the SDK client.
  let dgConn: any;
  try {
    dgConn = await deepgram.agent.v1.createConnection();
  } catch (error) {
    console.error("Failed to create Deepgram Agent connection:", error);
    try {
      clientWs.sendText(
        JSON.stringify({
          type: "Error",
          description:
            error instanceof Error ? error.message : "Failed to reach Deepgram",
          code: "PROVIDER_ERROR",
        })
      );
      clientWs.close(getSafeCloseCode(1011));
    } catch {
      // Client may already be closed
    }
    activeConnections.delete(clientWs as unknown as WebSocket);
    return;
  }
  clientWs.data.dgConn = dgConn;

  // Deepgram connection opened — voice agent sends Welcome message automatically
  dgConn.on("open", () => {
    console.log("Connected to Deepgram Agent API");
  });

  // Forward all messages from Deepgram to the client. Agent audio arrives as
  // binary (ArrayBuffer/Blob/Buffer); JSON events (Welcome / ConversationText /
  // ...) arrive as parsed objects. Preserve the exact frame types the browser
  // previously received.
  dgConn.on("message", (data: unknown) => {
    try {
      if (typeof data === "string") {
        clientWs.sendText(data);
      } else if (data instanceof ArrayBuffer) {
        clientWs.sendBinary(new Uint8Array(data));
      } else if (data instanceof Uint8Array || Buffer.isBuffer(data)) {
        clientWs.sendBinary(new Uint8Array(data as Uint8Array));
      } else if (data instanceof Blob) {
        // SDK delivers agent audio as a Blob; JSON.stringify(Blob) is "{}",
        // so unwrap to bytes before forwarding.
        data.arrayBuffer().then((buf) => {
          try { clientWs.sendBinary(new Uint8Array(buf)); } catch {}
        });
      } else {
        clientWs.sendText(JSON.stringify(data));
      }
    } catch {
      // Client may have disconnected — ignore send errors
    }
  });

  // Handle Deepgram connection errors
  dgConn.on("error", (error: any) => {
    console.error("Deepgram socket error:", error);
    try {
      clientWs.sendText(
        JSON.stringify({
          type: "Error",
          description: error?.message || "Deepgram connection error",
          code: "PROVIDER_ERROR",
        })
      );
    } catch {
      // Client may have disconnected
    }
  });

  // Handle Deepgram disconnect — close client with a safe code
  dgConn.on("close", () => {
    console.log("Deepgram connection closed");
    try {
      clientWs.close(getSafeCloseCode(1000));
    } catch {
      // Client may already be closed
    }
    activeConnections.delete(clientWs as unknown as WebSocket);
  });

  // Open the connection, then flush anything the browser queued early (the
  // client typically sends its Settings message immediately).
  try {
    dgConn.connect();
    await dgConn.waitForOpen();
    clientWs.data.dgReady = true;
    for (const item of clientWs.data.pending) {
      if (item.binary) {
        try {
          dgConn.sendMedia(item.data);
        } catch (error) {
          console.error("Failed to send buffered audio to Deepgram:", error);
        }
      } else {
        dispatchAgentControl(dgConn, item.msg);
      }
    }
    clientWs.data.pending = [];
  } catch (error) {
    console.error("Deepgram connection did not open:", error);
    try {
      clientWs.close(getSafeCloseCode(1011));
    } catch {
      // Client may already be closed
    }
  }
}

// ============================================================================
// SERVER START
// ============================================================================

console.log("\n" + "=".repeat(70));
console.log(`Backend API Server running at http://localhost:${config.port}`);
console.log("");
console.log(`GET  /api/session`);
console.log(`WS   /api/voice-agent (auth required)`);
console.log(`GET  /api/metadata`);
console.log("=".repeat(70) + "\n");

Bun.serve({
  port: config.port,
  hostname: config.host,

  /**
   * Main request handler — routes all incoming HTTP requests.
   * WebSocket upgrades for /api/voice-agent are handled here via server.upgrade().
   */
  async fetch(req: Request, server): Promise<Response> {
    const url = new URL(req.url);

    // Handle CORS preflight requests
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: getCorsHeaders() });
    }

    // --- WebSocket upgrade for /api/voice-agent ---
    if (url.pathname === "/api/voice-agent") {
      // Validate JWT from subprotocol before upgrading
      const protocols = req.headers.get("sec-websocket-protocol");
      const validProto = validateWsToken(protocols);

      if (!validProto) {
        console.log("WebSocket auth failed: invalid or missing token");
        return new Response("Unauthorized", { status: 401 });
      }

      console.log("Backend handling /api/voice-agent WebSocket (authenticated)");

      // Upgrade the HTTP request to a WebSocket connection
      const success = server.upgrade<WsData>(req, {
        data: { dgConn: null, dgReady: false, pending: [] },
        headers: {
          "Sec-WebSocket-Protocol": validProto,
        },
      });

      if (success) {
        // Bun returns undefined on successful upgrade; we return nothing
        return undefined as unknown as Response;
      }

      return new Response("WebSocket upgrade failed", { status: 500 });
    }

    // --- Session routes (unprotected) ---

    if (req.method === "GET" && url.pathname === "/api/session") {
      return handleGetSession();
    }

    if (req.method === "GET" && url.pathname === "/api/metadata") {
      return await handleMetadata();
    }

    if (req.method === "GET" && url.pathname === "/health") {
      return handleHealth();
    }

    // --- 404 for all other routes ---

    return Response.json(
      { error: "Not Found", message: "Endpoint not found" },
      { status: 404, headers: getCorsHeaders() }
    );
  },

  /**
   * WebSocket handlers for the voice agent proxy.
   * Bun.serve() requires a websocket object with lifecycle callbacks.
   */
  websocket: {
    /**
     * Called when a client WebSocket connection is opened.
     * Establishes the upstream connection to Deepgram.
     */
    open(ws: import("bun").ServerWebSocket<WsData>) {
      console.log("Client connected to /api/voice-agent");
      activeConnections.add(ws as unknown as WebSocket);
      // Fire-and-forget: connectToDeepgram opens the SDK socket and buffers any
      // early browser messages until it is ready.
      void connectToDeepgram(ws);
    },

    /**
     * Called when a message is received from the client.
     * Binary frames are mic audio; text frames are JSON control messages
     * (Settings / KeepAlive / Update* / Inject* / ...). Everything is forwarded
     * to Deepgram via the SDK, buffered until the socket is ready.
     */
    message(ws: import("bun").ServerWebSocket<WsData>, message: string | Buffer) {
      const dgConn = ws.data.dgConn;

      // Binary audio frame.
      if (typeof message !== "string") {
        const bytes = new Uint8Array(message);
        if (!ws.data.dgReady || !dgConn) {
          ws.data.pending.push({ binary: true, data: bytes });
          return;
        }
        try {
          dgConn.sendMedia(bytes);
        } catch (error) {
          console.error("Failed to send audio to Deepgram:", error);
        }
        return;
      }

      // Text frame — a JSON control message.
      let msg: any;
      try {
        msg = JSON.parse(message);
      } catch {
        console.warn("Ignoring non-JSON text message from client");
        return;
      }
      if (!ws.data.dgReady || !dgConn) {
        ws.data.pending.push({ binary: false, msg });
        return;
      }
      dispatchAgentControl(dgConn, msg);
    },

    /**
     * Called when the client WebSocket connection closes.
     * Cleans up the upstream Deepgram connection.
     */
    close(ws: import("bun").ServerWebSocket<WsData>, code: number, reason: string) {
      console.log(`Client disconnected: ${code} ${reason}`);
      try {
        ws.data?.dgConn?.close();
      } catch {
        // already closed
      }
      activeConnections.delete(ws as unknown as WebSocket);
    },

    /**
     * Called when a client WebSocket error occurs.
     * Cleans up the upstream Deepgram connection.
     */
    error(ws: import("bun").ServerWebSocket<WsData>, error: Error) {
      console.error("Client WebSocket error:", error);
      try {
        ws.data?.dgConn?.close();
      } catch {
        // already closed
      }
    },
  },
});

// ============================================================================
// GRACEFUL SHUTDOWN
// ============================================================================

/**
 * Graceful shutdown handler — closes all active WebSocket connections
 * and exits the process.
 * @param signal - The signal that triggered shutdown
 */
function gracefulShutdown(signal: string): void {
  console.log(`\n${signal} signal received: starting graceful shutdown...`);

  // Close all active WebSocket connections
  console.log(`Closing ${activeConnections.size} active WebSocket connection(s)...`);
  activeConnections.forEach((ws) => {
    try {
      ws.close(1001, "Server shutting down");
    } catch (error) {
      console.error("Error closing WebSocket:", error);
    }
  });

  console.log("Shutdown complete");
  process.exit(0);
}

// Handle shutdown signals
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

// Handle uncaught errors
process.on("uncaughtException", (error) => {
  console.error("Uncaught Exception:", error);
  gracefulShutdown("UNCAUGHT_EXCEPTION");
});

process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled Rejection at:", promise, "reason:", reason);
  gracefulShutdown("UNHANDLED_REJECTION");
});
