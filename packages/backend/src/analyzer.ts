import type {
  AnalysisInput,
  Assessment,
  CsrfSettings,
  InputField,
  Priority,
} from "./types";

const TOKENS = new Set([
  "csrf",
  "csrf_token",
  "csrftoken",
  "csrfmiddlewaretoken",
  "xsrf_token",
  "xsrftoken",
  "_csrf",
  "_token",
  "authenticity_token",
  "request_verification_token",
  "__requestverificationtoken",
  "anticsrf",
  "anti_csrf",
  "form_token",
  "formtoken",
]);
const TOKEN_HEADERS = new Set([
  "x_csrf_token",
  "x_csrf",
  "x_xsrf_token",
  "x_srf_token",
  "x_requested_with",
  "requestverificationtoken",
  "csrf_token",
]);
const AUTH_COOKIES = new Set([
  "session",
  "sessionid",
  "session_id",
  "sid",
  "jsessionid",
  "phpsessid",
  "aspsessionid",
  "asp_net_sessionid",
  "connect_sid",
  "auth",
  "auth_token",
  "access_token",
  "remember_me",
  "wordpress_logged_in",
]);
const SENSITIVE = new Set([
  "password",
  "passwd",
  "email",
  "phone",
  "profile",
  "account",
  "user",
  "admin",
  "role",
  "permission",
  "delete",
  "remove",
  "disable",
  "enable",
  "update",
  "change",
  "edit",
  "create",
  "invite",
  "transfer",
  "payment",
  "pay",
  "withdraw",
  "refund",
  "address",
  "mfa",
  "2fa",
  "totp",
  "api_key",
  "credential",
  "subscription",
  "checkout",
  "order",
  "upload",
  "message",
  "logout",
  "settings",
  "preference",
  "security",
  "username",
  "display_name",
  "first_name",
  "last_name",
]);
const UNSAFE = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const STATIC = new Set([
  "js",
  "css",
  "map",
  "png",
  "jpg",
  "jpeg",
  "gif",
  "svg",
  "ico",
  "woff",
  "woff2",
  "ttf",
  "mp4",
  "mp3",
  "pdf",
]);
const PLACEHOLDERS = new Set([
  "undefined",
  "null",
  "false",
  "changeme",
  "placeholder",
  "token",
  "none",
]);

export function analyze(
  input: AnalysisInput,
  settings: CsrfSettings,
): Assessment | undefined {
  const method = input.method.toUpperCase();
  const path = input.path || "/";
  const lowerPath = path.toLowerCase();
  if (
    settings.ignoredHosts.includes(input.host.toLowerCase()) ||
    settings.ignoredPaths.some((value) => lowerPath.includes(value))
  )
    return undefined;
  if (["HEAD", "OPTIONS", "TRACE"].includes(method)) return undefined;
  const websocket = isWebSocket(input.headers);
  const graph = graphQl(input);
  const workflow = workflowEvidence(input);
  const override = methodOverride(input);
  const sensitive =
    isSensitive(input, settings) ||
    workflow !== "" ||
    override !== "" ||
    graph.mutation;
  const stateChangingGet = method === "GET" && (sensitive || graph.persisted);
  if (
    !websocket &&
    !UNSAFE.has(method) &&
    !graph.mutation &&
    override === "" &&
    !stateChangingGet
  )
    return undefined;
  if (!websocket && isStatic(lowerPath) && !UNSAFE.has(method))
    return undefined;

  const auth = authentication(input, settings);
  if (
    !auth.ambient &&
    workflow === "" &&
    settings.sensitivity === "CONSERVATIVE"
  )
    return undefined;
  if (
    !auth.ambient &&
    workflow === "" &&
    settings.sensitivity === "BALANCED" &&
    !sensitive
  )
    return undefined;
  const token = tokenEvidence(input, settings, workflow !== "");
  const cookieDefense = cookieDefenseFor(input, auth.cookies);
  const forgeability = websocket
    ? "Browser WebSocket API can initiate a cross-site handshake; Origin enforcement is unverified"
    : exploitability(method, input.contentType);
  const browserForgeable = forgeability.startsWith("Browser-forgeable");
  let priority: Priority;
  let confidence: string;
  if (token.status === "Observed")
    [priority, confidence] = ["PROTECTED", "Medium"];
  else if (token.status === "Weak" || token.status === "Unknown")
    [priority, confidence] = ["REVIEW_2", "Medium"];
  else if (!auth.ambient) [priority, confidence] = ["REVIEW_3", "Low"];
  else if (
    websocket
      ? !cookieMitigatesWebSocket(cookieDefense)
      : sensitive && browserForgeable && !cookieMitigates(method, cookieDefense)
  )
    [priority, confidence] = [
      "REVIEW_1",
      token.status === "Missing" ? "High" : "Medium",
    ];
  else
    [priority, confidence] = [
      "REVIEW_2",
      token.status === "Missing" ? "Medium" : "Low",
    ];

  const origin = originEvidence(input);
  const fetch = fetchEvidence(input.headers);
  const cors = corsEvidence(input.responseHeaders, websocket);
  const action = websocket
    ? "WebSocket CSWSH handshake"
    : graph.action ||
      workflow ||
      (sensitive ? "Sensitive state change" : "State change");
  const firstReason = websocket
    ? "WebSocket upgrade uses browser-ambient credentials and requires CSWSH review"
    : graph.reason ||
      `${method} ${sensitive ? "targets a sensitive action" : "may change server state"}`;
  const reasons = [
    firstReason,
    auth.detail,
    token.detail,
    `Browser exploitability: ${forgeability}`,
    `Cookie defense: ${cookieDefense}`,
    `Fetch Metadata: ${fetch}`,
    `CORS: ${cors}`,
  ];
  if (override !== "")
    reasons.splice(
      1,
      0,
      `Method override requests ${override}; server handling is unverified`,
    );
  const custom = customHeaders(input.headers);
  if (custom !== "") reasons.splice(4, 0, custom);
  return {
    endpointKey: endpointKey(websocket ? "WS" : method, input, graph.operation),
    actionType: action,
    authEvidence: auth.detail,
    ambientAuthentication: auth.ambient,
    tokenEvidence: token.detail,
    tokenName: token.name,
    originEvidence: origin,
    fetchMetadataEvidence: fetch,
    corsEvidence: cors,
    cookieDefense,
    exploitability: forgeability,
    priority,
    confidence,
    reasons,
  };
}

function authentication(input: AnalysisInput, settings: CsrfSettings) {
  const authorization = header(input.headers, "authorization");
  if (/^(Basic|Digest) /i.test(authorization))
    return {
      ambient: true,
      detail: "Browser ambient Authorization authentication",
      cookies: [] as string[],
    };
  const all: string[] = [],
    likely: string[] = [];
  for (const part of header(input.headers, "cookie").split(";")) {
    const index = part.indexOf("=");
    if (index <= 0 || part.slice(index + 1).trim() === "") continue;
    const name = normalize(part.slice(0, index));
    all.push(name);
    if (
      AUTH_COOKIES.has(name) ||
      settings.customAuthCookies.includes(name) ||
      /sess|login|remember/.test(name)
    )
      likely.push(name);
  }
  if (likely.length > 0)
    return {
      ambient: true,
      detail: `Likely session cookie: ${likely.join(", ")}`,
      cookies: likely,
    };
  if (all.length > 0 && settings.sensitivity !== "CONSERVATIVE")
    return {
      ambient: true,
      detail: "Cookie authentication possible (cookie purpose unknown)",
      cookies: all,
    };
  if (/^Bearer /i.test(authorization))
    return {
      ambient: false,
      detail: "Bearer-only authentication is not normally ambient",
      cookies: [] as string[],
    };
  return {
    ambient: false,
    detail: "No browser-ambient authentication identified",
    cookies: [] as string[],
  };
}

function tokenEvidence(
  input: AnalysisInput,
  settings: CsrfSettings,
  oauth: boolean,
) {
  const fields: InputField[] = [...input.fields];
  for (const [name, values] of Object.entries(input.headers))
    for (const value of values)
      fields.push({ name, value, location: "HEADER" });
  let weak: { status: string; name: string; detail: string } | undefined;
  for (const field of fields) {
    const name = normalize(field.name);
    const known =
      TOKENS.has(name) ||
      TOKEN_HEADERS.has(name) ||
      settings.customTokenNames.includes(name) ||
      input.learnedTokenNames.includes(name) ||
      /csrf|xsrf|requesttoken|authenticitytoken/.test(name) ||
      (oauth && ["state", "relaystate", "relay_state"].includes(name));
    if (!known || field.location.toUpperCase().includes("COOKIE")) continue;
    if (name === "x_requested_with") {
      weak = {
        status: "Weak",
        name,
        detail: "X-Requested-With observed; server enforcement is unverified",
      };
      continue;
    }
    const tokenValue = field.value.trim();
    if (
      tokenValue.length < 8 ||
      PLACEHOLDERS.has(tokenValue.toLowerCase()) ||
      new Set(tokenValue).size < 4
    ) {
      weak = {
        status: "Weak",
        name,
        detail: `CSRF-like field is blank, short, or placeholder-like: ${name}`,
      };
      continue;
    }
    return {
      status: "Observed",
      name,
      detail: `CSRF token observed in ${field.location}: ${name} (validation unverified).`,
    };
  }
  if (weak !== undefined) return weak;
  if (input.requestBodyTruncated)
    return {
      status: "Unknown",
      name: "",
      detail:
        "Token status unknown because the request body exceeded the analysis limit",
    };
  if (
    /octet-stream|protobuf|grpc/i.test(input.contentType) &&
    input.body !== ""
  )
    return {
      status: "Unknown",
      name: "",
      detail: "Token status unknown for unsupported/opaque body",
    };
  return {
    status: "Missing",
    name: "",
    detail: "No CSRF token was identified",
  };
}

function graphQl(input: AnalysisInput) {
  const queries = input.fields
    .filter((f) => normalize(f.name) === "query")
    .map((f) => f.value);
  const requestedOperation = input.fields.find(
    (f) => normalize(f.name) === "operationname",
  )?.value;
  let operation =
    requestedOperation === undefined || requestedOperation === ""
      ? "anonymous"
      : requestedOperation;
  let persisted = input.fields.some(
    (f) =>
      normalize(f.name) === "extensions" && /persistedquery/i.test(f.value),
  );
  try {
    const root: unknown = JSON.parse(input.body);
    const items = Array.isArray(root) ? root : [root];
    for (const item of items)
      if (item !== null && typeof item === "object") {
        const value = item as Record<string, unknown>;
        if (typeof value.query === "string") queries.push(value.query);
        if (typeof value.operationName === "string")
          operation = value.operationName;
        if (
          JSON.stringify(value.extensions ?? "")
            .toLowerCase()
            .includes("persistedquery")
        )
          persisted = true;
      }
    if (Array.isArray(root)) persisted = true;
  } catch {
    if (input.body.trim() !== "") queries.push(input.body);
  }
  for (const query of queries) {
    const match = /\bmutation(?:\s+([A-Za-z_][A-Za-z0-9_]*))?/is.exec(query);
    if (match !== null) {
      const name =
        match[1] === undefined || match[1] === "" ? operation : match[1];
      return {
        mutation: true,
        persisted: false,
        operation: `mutation:${name}`,
        action: `GraphQL mutation: ${name}`,
        reason: "GraphQL mutation changes server state",
      };
    }
  }
  return {
    mutation: false,
    persisted: input.path.toLowerCase().includes("graphql") && persisted,
    operation: persisted ? `graphql:${operation}` : "",
    action: persisted
      ? "GraphQL persisted/batched operation (type unknown)"
      : "",
    reason: persisted
      ? "GraphQL persisted/batched operation requires manual state-change review"
      : "",
  };
}

function workflowEvidence(input: AnalysisInput): string {
  const path = normalize(input.path),
    names = new Set(input.fields.map((f) => normalize(f.name)));
  if (
    /oauth|oidc|saml|authorize|connect_account|link_account/.test(path) ||
    (path.includes("callback") &&
      ["state", "relaystate", "code"].some((n) => names.has(n)))
  )
    return "OAuth/account-linking workflow";
  if (/login|signin|sign_in|authenticate/.test(path))
    return "Login CSRF workflow";
  return "";
}

function methodOverride(input: AnalysisInput): string {
  for (const field of input.fields)
    if (
      ["_method", "method", "http_method", "x_http_method_override"].includes(
        normalize(field.name),
      ) &&
      UNSAFE.has(field.value.toUpperCase())
    )
      return field.value.toUpperCase();
  const value = header(input.headers, "x-http-method-override").toUpperCase();
  return UNSAFE.has(value) ? value : "";
}

function isSensitive(input: AnalysisInput, settings: CsrfSettings): boolean {
  const text = normalize(
    `${input.path} ${input.fields.map((f) => f.name).join(" ")}`,
  );
  return [...SENSITIVE, ...settings.customSensitiveWords].some(
    (word) => word !== "" && text.includes(normalize(word)),
  );
}
function exploitability(method: string, type: string): string {
  if (method === "GET") return "Browser-forgeable";
  if (method !== "POST")
    return "Reduced by non-simple method (CORS/preflight review required)";
  if (/application\/x-www-form-urlencoded|multipart\/form-data/i.test(type))
    return "Browser-forgeable";
  if (/text\/plain/i.test(type))
    return "Browser-forgeable shape; exact payload compatibility unverified";
  if (/json|xml/i.test(type)) return "Reduced by non-simple Content-Type";
  return type === ""
    ? "Unknown (Content-Type absent)"
    : "Reduced by non-simple Content-Type";
}
function cookieDefenseFor(input: AnalysisInput, cookies: string[]): string {
  if (cookies.length === 0) return "Unknown";
  const values = cookies.map((name) =>
    (input.cookieSameSite[name] ?? "unknown").toLowerCase(),
  );
  if (values.some((v) => v === "none")) return "SameSite=None";
  if (values.every((v) => v === "strict")) return "SameSite=Strict";
  if (values.some((v) => v === "lax")) return "SameSite=Lax/Strict";
  if (values.some((v) => v === "unspecified")) return "SameSite unspecified";
  return "SameSite unknown";
}
function originEvidence(input: AnalysisInput): string {
  const value =
    header(input.headers, "origin") || header(input.headers, "referer");
  if (value === "") return "Origin/Referer absent";
  if (value.toLowerCase() === "null")
    return "Origin: null observed; validation unverified";
  try {
    // eslint-disable-next-line compat/compat -- Caido's plugin runtime provides the URL API.
    return `${header(input.headers, "origin") ? "Origin" : "Referer"} ${new URL(value).origin === new URL(input.url).origin ? "same-origin" : "cross-origin"} observed; server validation unverified`;
  } catch {
    return "Origin/Referer observed but could not be parsed; validation unverified";
  }
}
function fetchEvidence(headers: Record<string, string[]>): string {
  const values = [
    ["sec-fetch-site", "Site"],
    ["sec-fetch-mode", "Mode"],
    ["sec-fetch-dest", "Dest"],
    ["sec-fetch-user", "User"],
  ]
    .map(([n, l]) => {
      const v = header(headers, n!);
      return v ? `${l}=${v}` : "";
    })
    .filter(Boolean);
  return values.length
    ? `${values.join(", ")}; enforcement unverified`
    : "not observed";
}
function corsEvidence(headers: Record<string, string[]>, ws: boolean): string {
  if (ws)
    return "CORS does not govern WebSocket handshakes; Origin enforcement is unverified";
  const origin = header(headers, "access-control-allow-origin"),
    credentials = header(headers, "access-control-allow-credentials");
  return origin
    ? `Allow-Origin=${origin}${credentials ? `, Allow-Credentials=${credentials}` : ""}; preflight policy unverified`
    : "no Access-Control-Allow-Origin observed";
}
function customHeaders(headers: Record<string, string[]>): string {
  const ignored = new Set([
    "accept",
    "accept-language",
    "content-language",
    "content-type",
    "host",
    "cookie",
    "origin",
    "referer",
    "user-agent",
    "connection",
    "content-length",
    "accept-encoding",
    "authorization",
    "cache-control",
    "pragma",
  ]);
  const names = Object.keys(headers)
    .filter(
      (n) =>
        !ignored.has(n.toLowerCase()) && !n.toLowerCase().startsWith("sec-"),
    )
    .sort();
  return names.length
    ? `Non-safelisted request headers observed: ${names.join(", ")}; whether the server requires them is unverified`
    : "";
}
function endpointKey(
  method: string,
  input: AnalysisInput,
  operation: string,
): string {
  const clean = input.path
    .split("?")[0]!
    .replace(/\/\d+(?=\/|$)/g, "/{id}")
    .replace(/\/[0-9a-f]{8}-[0-9a-f-]{27,}(?=\/|$)/gi, "/{id}")
    .replace(/\/[A-Za-z0-9_-]{20,}(?=\/|$)/g, "/{value}");
  return `${input.host.toLowerCase()}|${method}|${clean}${operation ? `|${operation}` : ""}`;
}
function header(values: Record<string, string[]>, name: string): string {
  const entry = Object.entries(values).find(
    ([key]) => key.toLowerCase() === name.toLowerCase(),
  );
  return entry?.[1]?.join(", ") ?? "";
}
function isWebSocket(headers: Record<string, string[]>): boolean {
  return (
    header(headers, "upgrade").toLowerCase() === "websocket" ||
    header(headers, "sec-websocket-key") !== ""
  );
}
function isStatic(path: string): boolean {
  const ext = path.split("?")[0]!.split(".").at(-1) ?? "";
  return STATIC.has(ext);
}
function cookieMitigates(method: string, defense: string): boolean {
  return (
    defense === "SameSite=Strict" ||
    (method !== "GET" && defense === "SameSite=Lax/Strict")
  );
}
function cookieMitigatesWebSocket(defense: string): boolean {
  return defense === "SameSite=Strict" || defense === "SameSite=Lax/Strict";
}
function normalize(value: string): string {
  return value
    .normalize("NFKC")
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, "_")
    .replace(/^_+|_+$/g, "");
}
