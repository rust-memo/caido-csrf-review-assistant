export class TrafficContext {
  private readonly cookies = new Map<string, Map<string, string>>();
  private readonly tokens = new Map<string, Set<string>>();

  clear(): void {
    this.cookies.clear();
    this.tokens.clear();
  }

  cookieSameSite(host: string): Record<string, string> {
    return Object.fromEntries(this.cookies.get(host.toLowerCase()) ?? []);
  }

  learnedTokenNames(host: string): string[] {
    return [...(this.tokens.get(host.toLowerCase()) ?? [])];
  }

  observe(
    host: string,
    responseHeaders: Record<string, string[]>,
    responseBody: string,
  ): void {
    const key = host.toLowerCase();
    const cookies = this.cookies.get(key) ?? new Map<string, string>();
    for (const value of headerValues(responseHeaders, "set-cookie")) {
      const parsed = parseSetCookie(value);
      if (parsed !== undefined) cookies.set(parsed.name, parsed.sameSite);
    }
    if (cookies.size > 0) this.cookies.set(key, cookies);

    if (responseBody === "") return;
    const tokens = this.tokens.get(key) ?? new Set<string>();
    for (const tag of responseBody.match(/<(?:input|meta)\b[^>]*>/giu) ?? []) {
      const attributes = parseAttributes(tag);
      const name = normalize(attributes.name ?? attributes.id ?? "");
      const value = attributes.value ?? attributes.content ?? "";
      const hidden =
        tag.toLowerCase().startsWith("<meta") ||
        (attributes.type ?? "").toLowerCase() === "hidden";
      if (
        hidden &&
        name !== "" &&
        value.length >= 8 &&
        (looksTokenLike(name) || (value.length >= 12 && looksRandom(value)))
      )
        tokens.add(name);
    }
    if (tokens.size > 0) this.tokens.set(key, tokens);
  }
}

function parseSetCookie(
  value: string,
): { name: string; sameSite: string } | undefined {
  const parts = value.split(";");
  const first = parts.shift() ?? "";
  const separator = first.indexOf("=");
  if (separator <= 0) return undefined;
  const name = normalize(first.slice(0, separator));
  if (name === "") return undefined;
  const sameSitePart = parts.find((part) => /^\s*samesite\s*=/i.test(part));
  const sameSite =
    sameSitePart === undefined
      ? "unspecified"
      : sameSitePart
          .slice(sameSitePart.indexOf("=") + 1)
          .trim()
          .toLowerCase();
  return { name, sameSite };
}

function headerValues(
  headers: Record<string, string[]>,
  name: string,
): string[] {
  return (
    Object.entries(headers).find(
      ([headerName]) => headerName.toLowerCase() === name,
    )?.[1] ?? []
  );
}

function parseAttributes(tag: string): Record<string, string> {
  const output: Record<string, string> = {};
  const pattern = /([^\s=/>]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gu;
  for (const match of tag.matchAll(pattern)) {
    const name = (match[1] ?? "").toLowerCase();
    output[name] = decodeEntities(match[2] ?? match[3] ?? match[4] ?? "");
  }
  return output;
}

function looksTokenLike(name: string): boolean {
  return /csrf|xsrf|token|nonce|authenticity|verification/.test(name);
}

function looksRandom(value: string): boolean {
  return /[A-Za-z]/.test(value) && /\d/.test(value) && new Set(value).size >= 8;
}

function decodeEntities(value: string): string {
  return value
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">");
}

function normalize(value: string): string {
  return value
    .normalize("NFKC")
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, "_")
    .replace(/^_+|_+$/g, "");
}
