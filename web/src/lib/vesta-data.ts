export type SourceId =
  "abuseipdb" | "otx" | "virustotal" | "threatfox" | "urlhaus" | "sgb" | "internetdb" | "mxtoolbox";
export type SourceStatus =
  "pending" | "match" | "no_match" | "unsupported" | "rate_limited" | "error";
export type IndicatorKind = "ipv4" | "ipv6" | "domain";

export type SourceResult = {
  source: SourceId;
  status: Exclude<SourceStatus, "pending">;
  summary: string;
  details: Record<string, unknown> | null;
  link?: string | null;
  elapsed_ms: number;
};

export type BreakdownEntry = {
  source: SourceId;
  points: number | null;
  max: number;
};

export type ScoreSnapshot = {
  value: number | null;
  evaluated: number;
  applicable: number;
  provisional: boolean;
  breakdown: BreakdownEntry[];
};

export type UsageSnapshot = {
  searches_24h: number;
  requests_24h: Record<string, number>;
  abuseipdb_today_utc: number;
  virustotal_minute: number;
  virustotal_24h: number;
};

export type NewsCategory = "news" | "official" | "privacy" | "cve" | "ioc";
export type NewsQuery = Partial<
  Record<
    | "q"
    | "category"
    | "source"
    | "content_type"
    | "priority"
    | "verification"
    | "region"
    | "active_exploitation"
    | "from_date"
    | "to_date"
    | "sort"
    | "page",
    string
  >
>;
export type NewsEvaluation = {
  content_type: string;
  priority: "critical" | "high" | "medium" | "low" | "general";
  verification: string;
  rank_score: number;
  rank_components: Record<string, number>;
  reasons: string[];
  indicators: { cves: string[]; ips: string[]; domains: string[] };
  active_exploitation: boolean;
  region: string;
  source_count: number;
  independent_source_count: number;
};
export type NewsEvent = {
  id: string;
  title: string;
  item_ids: string[];
  sources: { name: string; url: string; published_at: string | null }[];
  timeline: { item_id: string; title: string; published_at: string | null; url: string }[];
  independent_source_count: number;
};

export type NewsItem = {
  id: string;
  source_id: string;
  source: string;
  category: NewsCategory;
  title: string;
  summary: string;
  url: string;
  published_at: string | null;
  date_only?: boolean;
  evaluation?: NewsEvaluation;
  event_id?: string;
  dates?: { published_at: string | null; updated_at: string | null; rss_added_at: string | null };
  cve_data?: {
    id: string;
    published_at: string | null;
    updated_at: string | null;
    rss_added_at: string | null;
    cvss: { score: number; version: string } | null;
    products: string[];
    kev: boolean | null;
    kev_added_at: string | null;
    sources: (string | null)[];
  } | null;
};

export type NewsSnapshot = {
  items: NewsItem[];
  sources: {
    id: string;
    name: string;
    category: NewsCategory;
    url: string;
    status: "ok" | "error";
    count: number;
    health_state?: string;
    checked_at?: string | null;
    last_success_at?: string | null;
    latest_item_published_at?: string | null;
    cache_age_seconds?: number | null;
    http_status?: number | null;
    error_kind?: string | null;
    expected_frequency?: string | null;
  }[];
  official_links: { name: string; description: string; url: string }[];
  fetched_at: string;
  stale?: boolean;
  tweets: TweetsSnapshot;
  events?: NewsEvent[];
  cve_radar?: { new: string[]; known_exploited: string[] };
  pagination?: { page: number; page_size: number; total: number };
  enrichment?: { kev_available: boolean; kev_stale: boolean; nvd_enriched: number };
};

export type TweetMedia = {
  type: string;
  url: string | null;
  local: string | null;
  width?: number | null;
  height?: number | null;
};

export type TweetItem = {
  id: string;
  created_at: string | null;
  text: string;
  lang: string | null;
  favorite_count: number;
  retweet_count: number;
  reply_count: number;
  quote_count: number;
  view_count: number;
  username: string;
  name: string | null;
  media: TweetMedia[];
  evaluation?: {
    priority: string;
    verification: string;
    label: string;
    claim_type?: string;
    account_identity?: string;
    independent_confirmation?: boolean;
    indicators: { cves: string[]; ips: string[]; domains: string[] };
  };
  group_id?: string;
  linked_event_id?: string | null;
};

export type TweetsSnapshot = {
  accounts: {
    username: string;
    status: string | null;
    fetched_at: string | null;
    count: number;
  }[];
  tweets: TweetItem[];
  fetched_at: string;
};

export type SearchStartEvent = {
  event: "start";
  indicator: string;
  kind: IndicatorKind;
  sources: SourceId[];
};

export type SearchDnsEvent = {
  event: "dns";
  status: "ok" | "timeout" | "error" | "no_public_ip";
  addresses: string[];
  selected: string | null;
};

export type SearchResultEvent = SourceResult & {
  event: "result";
  indicator: string;
  kind: IndicatorKind;
};

export type SearchScoreEvent = ScoreSnapshot & {
  event: "score";
  indicator: string;
  kind: IndicatorKind;
};

export type SearchDoneEvent = { event: "done" };

export type SearchEvent =
  SearchStartEvent | SearchDnsEvent | SearchResultEvent | SearchScoreEvent | SearchDoneEvent;

export const SOURCE_ORDER: SourceId[] = [
  "abuseipdb",
  "otx",
  "virustotal",
  "threatfox",
  "urlhaus",
  "sgb",
  "internetdb",
  "mxtoolbox",
];

export const SOURCE_NAMES: Record<SourceId, string> = {
  abuseipdb: "AbuseIPDB",
  otx: "AlienVault OTX",
  virustotal: "VirusTotal",
  threatfox: "ThreatFox",
  urlhaus: "URLhaus",
  sgb: "Siber Güvenlik Bşk.",
  internetdb: "Shodan InternetDB",
  mxtoolbox: "MXToolbox",
};

export const STATUS_LABELS: Record<SourceStatus, string> = {
  pending: "Bekleniyor",
  match: "Eşleşme",
  no_match: "Kayıt yok",
  unsupported: "Destek dışı",
  rate_limited: "Limit doldu",
  error: "Hata",
};

export function detectIndicatorType(value: string): "ipv4" | "domain" | null {
  const input = value.trim();
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(input)) {
    return input.split(".").every((part) => Number(part) <= 255) ? "ipv4" : null;
  }
  if (/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i.test(input)) return "domain";
  return null;
}

async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, { credentials: "same-origin", ...options });
  if (!response.ok) {
    let detail = `İstek başarısız oldu (${response.status}).`;
    try {
      const data = (await response.json()) as { detail?: unknown };
      if (typeof data.detail === "string") detail = data.detail;
    } catch {
      /* yanıt JSON değil */
    }
    throw new ApiError(detail, response.status);
  }
  return (await response.json()) as T;
}

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export async function fetchSession() {
  return api<{ authenticated: boolean }>("/api/session");
}

export async function login(password: string) {
  return api<{ authenticated: boolean }>("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password }),
  });
}

export async function logout() {
  return api<{ authenticated: boolean }>("/api/logout", { method: "POST" });
}

export async function fetchUsage() {
  return api<UsageSnapshot>("/api/usage");
}

export async function fetchNews(signal?: AbortSignal, fresh = false, query: NewsQuery = {}) {
  const params = new URLSearchParams();
  if (fresh) params.set("fresh", "1");
  Object.entries(query).forEach(([key, value]) => {
    if (value) params.set(key, value);
  });
  const suffix = params.size ? `?${params}` : "";
  return api<NewsSnapshot>(`/api/news${suffix}`, { signal: signal ?? null });
}

export async function searchStream(
  indicator: string,
  signal: AbortSignal,
  onEvent: (event: SearchEvent) => void,
) {
  const response = await fetch("/api/search", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ indicator }),
    signal,
    credentials: "same-origin",
  });
  if (!response.ok) {
    let detail = `Sorgu başlatılamadı (${response.status}).`;
    try {
      const data = (await response.json()) as { detail?: unknown };
      if (typeof data.detail === "string") detail = data.detail;
    } catch {
      /* yanıt JSON değil */
    }
    throw new ApiError(detail, response.status);
  }
  const reader = response.body?.getReader();
  if (!reader) throw new ApiError("Yanıt akışı okunamadı.", 0);
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let at: number;
      while ((at = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, at);
        buffer = buffer.slice(at + 1);
        if (!line) continue;
        onEvent(JSON.parse(line) as SearchEvent);
      }
    }
  } finally {
    reader.releaseLock();
  }
}

const PORT_SERVICES: Record<number, string> = {
  20: "FTP-Data",
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  25: "SMTP",
  53: "DNS",
  67: "DHCP",
  68: "DHCP",
  69: "TFTP",
  80: "HTTP",
  110: "POP3",
  111: "RPC",
  123: "NTP",
  135: "MSRPC",
  137: "NetBIOS",
  138: "NetBIOS",
  139: "NetBIOS",
  143: "IMAP",
  161: "SNMP",
  162: "SNMP-Trap",
  389: "LDAP",
  443: "HTTPS",
  445: "SMB",
  465: "SMTPS",
  514: "Syslog",
  515: "LPD",
  548: "AFP",
  554: "RTSP",
  587: "SMTP",
  631: "IPP",
  636: "LDAPS",
  873: "Rsync",
  902: "VMware",
  993: "IMAPS",
  995: "POP3S",
  1025: "MSRPC",
  1080: "SOCKS",
  1194: "OpenVPN",
  1433: "MSSQL",
  1521: "Oracle",
  1723: "PPTP",
  1900: "SSDP",
  2049: "NFS",
  2222: "SSH",
  2375: "Docker",
  2376: "Docker TLS",
  3000: "Grafana",
  3306: "MySQL",
  3389: "RDP",
  5000: "UPnP",
  5060: "SIP",
  5432: "PostgreSQL",
  5555: "ADB",
  5601: "Kibana",
  5900: "VNC",
  5985: "WinRM HTTP",
  5986: "WinRM HTTPS",
  6379: "Redis",
  6443: "Kubernetes",
  7001: "WebLogic",
  8000: "HTTP Alt",
  8009: "AJP",
  8080: "HTTP Proxy",
  8443: "HTTPS Alt",
  8888: "HTTP Alt",
  9000: "SonarQube",
  9042: "Cassandra",
  9090: "Prometheus",
  9200: "Elasticsearch",
  9300: "Elasticsearch",
  10000: "Webmin",
  11211: "Memcached",
  15672: "RabbitMQ",
  27017: "MongoDB",
};

export function portService(port: number) {
  return PORT_SERVICES[port] ?? "Bilinmiyor";
}

const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/i;

export function cveLink(value: string) {
  if (!CVE_PATTERN.test(value)) return null;
  return `https://nvd.nist.gov/vuln/detail/${value.toUpperCase()}`;
}

export const SOURCE_TAG: Record<SourceId, string> = {
  abuseipdb: "ABUSE",
  otx: "OTX",
  virustotal: "VT",
  threatfox: "TFX",
  urlhaus: "URLH",
  sgb: "SGB",
  internetdb: "IDB",
  mxtoolbox: "MXTB",
};

export function flagEmoji(isoCode: string) {
  const code = isoCode.trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(code)) return null;
  return String.fromCodePoint(...[...code].map((char) => 0x1f1e6 + char.charCodeAt(0) - 65));
}

export function parseCpe(cpe: string) {
  const parts = cpe.split(":");
  if (parts[0] !== "cpe") return null;
  const version = parts[1];
  const rest = version === "2.3" ? parts.slice(3) : parts.slice(2);
  if (rest.length < 2) return null;
  const vendor = rest[0];
  const product = rest[1];
  const release = rest[2];
  if (!vendor || !product || (vendor === "*" && product === "*")) return null;
  return {
    vendor: vendor === "*" ? null : vendor,
    product: product === "*" ? null : product,
    version: release && release !== "*" && release !== "-" && release !== "" ? release : null,
  };
}

export function cpeLabel(cpe: string) {
  const parsed = parseCpe(cpe);
  if (!parsed) return null;
  const name = [parsed.vendor, parsed.product].filter(Boolean).join(" ");
  if (!name) return null;
  return parsed.version ? `${name} (${parsed.version})` : name;
}
