import { createHash, timingSafeEqual } from "node:crypto";
import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { parseAllowedHosts, resolveUrl, ResolverError } from "./resolver.js";

const API_KEY = process.env.API_KEY || "";
const ALLOWED_HOSTS = parseAllowedHosts();

if (API_KEY.length < 32) {
  console.error("Startup refused: configure API_KEY with at least 32 characters in the Render environment.");
  process.exit(1);
}

if (ALLOWED_HOSTS.size === 0) {
  console.error("Startup refused: ALLOWED_HOSTS must contain at least one hostname.");
  process.exit(1);
}

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet());
app.use(express.json({ limit: "4kb", strict: true }));
app.use((_req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});

const tooManyRequestsBody = {
  success: false,
  error: {
    code: "RATE_LIMITED",
    message: "Too many requests. Try again later."
  }
};

const ipLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: tooManyRequestsBody
});

const keyLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 60,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  keyGenerator: (req) => createHash("sha256")
    .update(req.get("authorization") || "missing")
    .digest("hex"),
  message: tooManyRequestsBody
});

function authenticate(req, res, next) {
  const match = /^Bearer ([A-Za-z0-9._~-]{32,200})$/.exec(req.get("authorization") || "");
  if (!match) {
    res.status(401).json({
      success: false,
      error: { code: "UNAUTHORIZED", message: "Provide a valid Bearer API key." }
    });
    return;
  }

  const supplied = Buffer.from(match[1], "utf8");
  const expected = Buffer.from(API_KEY, "utf8");
  const valid = supplied.length === expected.length && timingSafeEqual(supplied, expected);

  if (!valid) {
    res.status(401).json({
      success: false,
      error: { code: "UNAUTHORIZED", message: "The API key is invalid." }
    });
    return;
  }

  next();
}

app.get("/", (_req, res) => {
  res.json({
    name: "Secure URL Resolver API",
    version: "1.0.0",
    endpoints: {
      health: "GET /healthz",
      resolve: "POST /v1/resolve"
    }
  });
});

app.get("/healthz", (_req, res) => {
  res.status(200).json({ status: "ok" });
});

app.post("/v1/resolve", ipLimiter, authenticate, keyLimiter, async (req, res, next) => {
  try {
    if (!req.body || Array.isArray(req.body) || typeof req.body !== "object") {
      res.status(400).json({
        success: false,
        error: { code: "INVALID_BODY", message: "Send a JSON object containing a url field." }
      });
      return;
    }

    const result = await resolveUrl(req.body.url, { allowedHosts: ALLOWED_HOSTS });
    res.status(200).json({
      success: true,
      original_url: result.originalUrl,
      resolved_url: result.resolvedUrl,
      redirects_followed: result.redirectsFollowed,
      http_status: result.httpStatus
    });
  } catch (error) {
    next(error);
  }
});

app.use((error, _req, res, next) => {
  if (res.headersSent) {
    next(error);
    return;
  }

  if (error && error.type === "entity.too.large") {
    res.status(413).json({
      success: false,
      error: { code: "BODY_TOO_LARGE", message: "The request body is too large." }
    });
    return;
  }

  if (error instanceof SyntaxError && error.status === 400) {
    res.status(400).json({
      success: false,
      error: { code: "INVALID_JSON", message: "The request body must be valid JSON." }
    });
    return;
  }

  if (error instanceof ResolverError) {
    res.status(error.statusCode).json({
      success: false,
      error: { code: error.code, message: error.message }
    });
    return;
  }

  console.error("Unhandled API error:", error && error.message ? error.message : "unknown error");
  res.status(500).json({
    success: false,
    error: { code: "INTERNAL_ERROR", message: "An internal error occurred." }
  });
});

const port = Number.parseInt(process.env.PORT || "3000", 10);
const server = app.listen(port, "0.0.0.0", () => {
  console.log("Secure URL Resolver API listening on port " + port);
});

server.requestTimeout = 10000;
server.headersTimeout = 12000;
server.keepAliveTimeout = 5000;
