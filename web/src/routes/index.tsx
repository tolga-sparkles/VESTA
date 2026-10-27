import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import "leaflet/dist/leaflet.css";
import {
  Search,
  ChevronDown,
  ChevronRight,
  Clock3,
  ExternalLink,
  Database,
  Info,
  LockKeyhole,
  Braces,
  X,
  Copy,
  Check,
  LoaderCircle,
  ShieldCheck,
  KeyRound,
  LogOut,
  MapPin,
  Building2,
  Router,
  Server,
  Globe,
  Shield,
  Cpu,
  Newspaper,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { SourceMark } from "@/components/source-mark";
import { NewsView } from "@/components/news-view";
import { SocTicker } from "@/components/soc-ticker";
import {
  ApiError,
  SOURCE_ORDER,
  SOURCE_NAMES,
  SOURCE_TAG,
  STATUS_LABELS,
  type IndicatorKind,
  type SourceId,
  type SourceResult,
  type ScoreSnapshot,
  type SearchDnsEvent,
  type UsageSnapshot,
  type NewsSnapshot,
  type NewsQuery,
  detectIndicatorType,
  fetchSession,
  login as apiLogin,
  logout as apiLogout,
  fetchUsage,
  fetchNews,
  searchStream,
  portService,
  cveLink,
  flagEmoji,
  cpeLabel,
} from "@/lib/vesta-data";
import {
  contributionRows,
  displayCountry,
  resolveIpLocation,
  type CountryRow,
} from "@/lib/analysis-view";

const GAUGE_CIRCUMFERENCE = 2 * Math.PI * 52;

export const Route = createFileRoute("/")({
  component: Vesta,
});

type StartInfo = { indicator: string; kind: IndicatorKind; sources: SourceId[] };

type TaggedEntry = { value: string; sources: SourceId[] };

function mergeEntries(entries: { value: string; source: SourceId }[]): TaggedEntry[] {
  const map = new Map<string, SourceId[]>();
  for (const entry of entries) {
    if (!entry.value) continue;
    const list = map.get(entry.value) ?? [];
    if (!list.includes(entry.source)) list.push(entry.source);
    map.set(entry.value, list);
  }
  return [...map.entries()].map(([value, sources]) => ({ value, sources }));
}

function buildCountryRows(
  otx: Record<string, unknown> | null | undefined,
  abuse: Record<string, unknown> | null | undefined,
  virustotal: Record<string, unknown> | null | undefined,
): CountryRow[] {
  const rows: CountryRow[] = [];
  const add = (code: unknown, name: unknown, source: SourceId) => {
    if (typeof code !== "string" || !code.trim()) return;
    const cleanCode = code.trim().toUpperCase();
    const existing = rows.find((row) => row.code.toUpperCase() === cleanCode);
    if (existing) {
      if (!existing.sources.includes(source)) existing.sources.push(source);
      if (!existing.name && typeof name === "string" && name.trim()) existing.name = name.trim();
      return;
    }
    rows.push({
      code: cleanCode,
      name: typeof name === "string" && name.trim() ? name.trim() : null,
      sources: [source],
    });
  };
  add(otx?.country_code, otx?.country_name, "otx");
  add(abuse?.countryCode, abuse?.countryName ?? abuse?.countryCode, "abuseipdb");
  add(virustotal?.country, null, "virustotal");
  return rows;
}

function SourceTags({ sources }: { sources: SourceId[] }) {
  return (
    <span className="profile-sources">
      {sources.map((source) => (
        <span key={source} className="profile-source" title={SOURCE_NAMES[source]}>
          {SOURCE_TAG[source]}
        </span>
      ))}
    </span>
  );
}

function ProfileField({
  label,
  icon,
  children,
}: {
  label: string;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="profile-field">
      <label>
        {icon}
        {label}
      </label>
      <div className="profile-values">{children}</div>
    </div>
  );
}

function ProfileRows({
  rows,
  emptyLabel = "Veri yok",
}: {
  rows: TaggedEntry[];
  emptyLabel?: string;
}) {
  if (!rows.length) return <span className="profile-none">{emptyLabel}</span>;
  return (
    <>
      {rows.map((row) => (
        <div className="profile-row" key={`${row.value}:${row.sources.join(",")}`}>
          <span className="profile-text">{row.value}</span>
          <SourceTags sources={row.sources} />
        </div>
      ))}
    </>
  );
}

function ProfileChips({
  rows,
  emptyLabel = "Veri yok",
}: {
  rows: TaggedEntry[];
  emptyLabel?: string;
}) {
  if (!rows.length) return <span className="profile-none">{emptyLabel}</span>;
  return (
    <div className="profile-chips">
      {rows.map((row) => (
        <span className="profile-chip" key={`${row.value}:${row.sources.join(",")}`}>
          {row.value}
          <SourceTags sources={row.sources} />
        </span>
      ))}
    </div>
  );
}

function LocationMap({ lat, lng }: { lat: number; lng: number }) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [mapError, setMapError] = useState(false);
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    let disposed = false;
    let map: import("leaflet").Map | null = null;
    const observer =
      typeof ResizeObserver === "undefined"
        ? null
        : new ResizeObserver(() => map?.invalidateSize({ pan: false }));
    observer?.observe(container);
    void import("leaflet")
      .then(({ default: L }) => {
        if (disposed) return;
        let fallbackStarted = false;
        map = L.map(container, {
          center: [lat, lng],
          zoom: 3,
          scrollWheelZoom: false,
          zoomControl: true,
        });
        const primaryTiles = L.tileLayer("/api/map-tiles/{z}/{x}/{y}.png", {
          attribution:
            '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> katkıda bulunanlar, &copy; <a href="https://carto.com/attribution/">CARTO</a>',
          maxZoom: 20,
        });
        primaryTiles
          .on("tileerror", () => {
            if (fallbackStarted || disposed || !map) return;
            fallbackStarted = true;
            map.removeLayer(primaryTiles);
            L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
              attribution:
                '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> katkıda bulunanlar',
              className: "location-fallback-tile",
              maxZoom: 19,
            })
              .on("tileerror", () => setMapError(true))
              .on("tileload", () => setMapError(false))
              .addTo(map);
          })
          .on("tileload", () => {
            if (!fallbackStarted) setMapError(false);
          })
          .addTo(map);
        L.circleMarker([lat, lng], {
          radius: 7,
          color: "#ffffff",
          weight: 2,
          fillColor: "#9d6bff",
          fillOpacity: 0.95,
        }).addTo(map);
      })
      .catch(() => {
        if (!disposed) setMapError(true);
      });
    return () => {
      disposed = true;
      observer?.disconnect();
      map?.remove();
    };
  }, [lat, lng]);
  return (
    <div className="location-map-wrap">
      <div ref={containerRef} className="location-map" aria-label="IP konum haritası" />
      {mapError && (
        <span className="location-map-error" role="status">
          Harita yüklenemedi; ülke bilgisi aşağıda gösteriliyor.
        </span>
      )}
    </div>
  );
}

export function Vesta() {
  const [authenticated, setAuthenticated] = useState<boolean | null>(null);
  const [activeView, setActiveView] = useState<"analysis" | "news">("analysis");
  const [usageOpen, setUsageOpen] = useState(false);
  const [sessionOpen, setSessionOpen] = useState(false);
  const [indicator, setIndicator] = useState("");
  const [start, setStart] = useState<StartInfo | null>(null);
  const [results, setResults] = useState<Partial<Record<SourceId, SourceResult>>>({});
  const [score, setScore] = useState<ScoreSnapshot | null>(null);
  const [ipResults, setIpResults] = useState<Partial<Record<SourceId, SourceResult>>>({});
  const [ipScore, setIpScore] = useState<ScoreSnapshot | null>(null);
  const [dns, setDns] = useState<SearchDnsEvent | null>(null);
  const [activeScope, setActiveScope] = useState<"domain" | "ip">("domain");
  const [analysisDone, setAnalysisDone] = useState(false);
  const [openSource, setOpenSource] = useState<SourceId | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [usage, setUsage] = useState<UsageSnapshot | null>(null);
  const [news, setNews] = useState<NewsSnapshot | null>(null);
  const [newsLoading, setNewsLoading] = useState(false);
  const [newsError, setNewsError] = useState("");
  const [newsRefreshKey, setNewsRefreshKey] = useState(0);
  const [newsQuery, setNewsQuery] = useState<NewsQuery>({});
  const newsFreshRef = useRef(false);
  const [jsonSource, setJsonSource] = useState<SourceResult | null>(null);
  const [copied, setCopied] = useState(false);
  const [password, setPassword] = useState("");
  const [loginError, setLoginError] = useState("");
  const [loginBusy, setLoginBusy] = useState(false);
  const controllerRef = useRef<AbortController | null>(null);
  const generationRef = useRef(0);

  useEffect(() => {
    fetchSession()
      .then((data) => setAuthenticated(data.authenticated))
      .catch(() => setAuthenticated(false));
  }, []);

  useEffect(() => {
    if (!authenticated) return;
    const controller = new AbortController();
    setNewsLoading(true);
    setNewsError("");
    const fresh = newsFreshRef.current;
    newsFreshRef.current = false;
    fetchNews(controller.signal, fresh, newsQuery)
      .then((data) => {
        if (!controller.signal.aborted) setNews(data);
      })
      .catch((caught) => {
        if (!controller.signal.aborted) {
          setNewsError(caught instanceof Error ? caught.message : "Haberler yüklenemedi.");
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setNewsLoading(false);
      });
    return () => controller.abort();
  }, [authenticated, newsRefreshKey, newsQuery]);

  useEffect(() => {
    if (!authenticated) return;
    const refresh = window.setInterval(() => setNewsRefreshKey((key) => key + 1), 600_000);
    return () => window.clearInterval(refresh);
  }, [authenticated]);

  useEffect(
    () => () => {
      controllerRef.current?.abort();
    },
    [],
  );

  useEffect(() => {
    if (!jsonSource) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setJsonSource(null);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [jsonSource]);

  async function refreshUsage() {
    try {
      setUsage(await fetchUsage());
    } catch {
      /* oturum sona erdiyse kullanım satırı boş kalır */
    }
  }

  async function handleLogin(event: React.FormEvent) {
    event.preventDefault();
    setLoginBusy(true);
    setLoginError("");
    try {
      await apiLogin(password);
      setPassword("");
      setAuthenticated(true);
      void refreshUsage();
    } catch (caught) {
      setLoginError(caught instanceof Error ? caught.message : "Giriş yapılamadı.");
    } finally {
      setLoginBusy(false);
    }
  }

  async function handleLogout() {
    generationRef.current++;
    controllerRef.current?.abort();
    setSessionOpen(false);
    try {
      await apiLogout();
    } catch {
      /* çerez zaten geçersizse de çıkış yapılır */
    }
    setAuthenticated(false);
    setResults({});
    setScore(null);
    setIpResults({});
    setIpScore(null);
    setDns(null);
    setStart(null);
    setAnalysisDone(false);
    setUsage(null);
    setNews(null);
    setActiveView("analysis");
  }

  function analyze(event: React.FormEvent) {
    event.preventDefault();
    if (!detectIndicatorType(indicator)) {
      setError("Geçerli bir IPv4 adresi veya alan adı girin.");
      return;
    }
    setError("");
    setLoading(true);
    setOpenSource(null);
    setResults({});
    setScore(null);
    setIpResults({});
    setIpScore(null);
    setDns(null);
    setStart(null);
    setAnalysisDone(false);
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    const generation = ++generationRef.current;
    let sawDone = false;
    searchStream(indicator, controller.signal, (event) => {
      if (generation !== generationRef.current) return;
      if (event.event === "start") {
        setStart({ indicator: event.indicator, kind: event.kind, sources: event.sources });
        setActiveScope(event.kind === "domain" ? "domain" : "ip");
      } else if (event.event === "dns") {
        setDns(event);
      } else if (event.event === "result") {
        if (event.kind === "domain") setResults((prev) => ({ ...prev, [event.source]: event }));
        else setIpResults((prev) => ({ ...prev, [event.source]: event }));
      } else if (event.event === "score") {
        if (event.kind === "domain") setScore(event);
        else setIpScore(event);
      } else if (event.event === "done") {
        sawDone = true;
        setAnalysisDone(true);
        setLoading(false);
      }
    })
      .then(() => {
        if (generation !== generationRef.current) return;
        setLoading(false);
        if (!sawDone) setError("Sorgu akışı tamamlanmadı; eksik sonuçlar olabilir.");
        void refreshUsage();
      })
      .catch((caught) => {
        if (generation !== generationRef.current) return;
        setLoading(false);
        if (caught instanceof ApiError && caught.status === 401) {
          setAuthenticated(false);
          return;
        }
        if (!(caught instanceof DOMException && caught.name === "AbortError")) {
          setError(caught instanceof Error ? caught.message : "Sorgu tamamlanamadı.");
        }
      });
  }

  const isDomainSearch = start?.kind === "domain";
  const displayResults = isDomainSearch && activeScope === "domain" ? results : ipResults;
  const displayScore = isDomainSearch && activeScope === "domain" ? score : ipScore;
  const profileResults = ipResults;
  const profileKind = dns?.selected
    ? dns.selected.includes(":")
      ? "ipv6"
      : "ipv4"
    : (start?.kind ?? null);
  const json = JSON.stringify(
    {
      indicator:
        isDomainSearch && activeScope === "ip" ? dns?.selected : (start?.indicator ?? indicator),
      source: jsonSource?.source,
      status: jsonSource?.status,
      summary: jsonSource?.summary,
      details: jsonSource?.details,
      elapsed_ms: jsonSource?.elapsed_ms,
      link: jsonSource?.link,
    },
    null,
    2,
  );
  const sourceCount = start?.sources.length ?? SOURCE_ORDER.length;
  const completed = Object.keys(displayResults).length;
  const internetdbResult = profileResults.internetdb;
  const internetPorts = Array.isArray(internetdbResult?.details?.ports)
    ? (internetdbResult.details.ports as number[])
    : [];
  const portMessage = !internetdbResult
    ? isDomainSearch && dns && !dns.selected
      ? "DNS'den genel IP bulunamadığı için port sorgusu yapılamadı."
      : loading || start
        ? "InternetDB yanıtı bekleniyor."
        : "Analiz bekleniyor."
    : internetdbResult.status === "unsupported" ||
        internetdbResult.status === "error" ||
        internetdbResult.status === "rate_limited"
      ? internetdbResult.summary
      : "Bu kaynakta açık port kaydı bulunamadı.";

  const profileAbuse = profileResults.abuseipdb?.details;
  const profileOtx = profileResults.otx?.details;
  const profileVt = profileResults.virustotal?.details;
  const profileIdb = internetdbResult?.details;

  const countryRows = buildCountryRows(profileOtx, profileAbuse, profileVt);
  const asnRows = (() => {
    const rows: TaggedEntry[] = [];
    const vtAsn = typeof profileVt?.asn === "number" ? profileVt.asn : null;
    const vtOwner =
      typeof profileVt?.as_owner === "string" && profileVt.as_owner.trim()
        ? profileVt.as_owner.trim()
        : "";
    const otxRaw = typeof profileOtx?.asn === "string" ? profileOtx.asn.trim() : "";
    const otxAsn = /^as(\d+)/i.exec(otxRaw)?.[1] ? `AS${/^as(\d+)/i.exec(otxRaw)?.[1]}` : null;
    if (vtAsn !== null) {
      rows.push({ value: `AS${vtAsn}${vtOwner ? ` · ${vtOwner}` : ""}`, sources: ["virustotal"] });
    }
    if (otxAsn) {
      const vtMatch = rows.find(
        (row) => row.value.startsWith(`${otxAsn} `) || row.value === otxAsn,
      );
      if (vtMatch) vtMatch.sources.push("otx");
      else rows.push({ value: otxRaw.replace(/^as\s*/i, "AS"), sources: ["otx"] });
    }
    return rows;
  })();
  const ispRows = mergeEntries(
    typeof profileAbuse?.isp === "string" && profileAbuse.isp.trim()
      ? [{ value: profileAbuse.isp.trim(), source: "abuseipdb" as SourceId }]
      : [],
  );
  const usageRows = mergeEntries(
    typeof profileAbuse?.usageType === "string" && profileAbuse.usageType.trim()
      ? [{ value: profileAbuse.usageType.trim(), source: "abuseipdb" as SourceId }]
      : [],
  );
  const domainRows = mergeEntries(
    typeof profileAbuse?.domain === "string" && profileAbuse.domain.trim()
      ? [{ value: profileAbuse.domain.trim(), source: "abuseipdb" as SourceId }]
      : [],
  );
  const hostnameRows = mergeEntries([
    ...(Array.isArray(profileIdb?.hostnames)
      ? (profileIdb.hostnames as unknown[])
          .filter((entry): entry is string => typeof entry === "string" && entry.trim() !== "")
          .map((value) => ({ value, source: "internetdb" as SourceId }))
      : []),
    ...(Array.isArray(profileAbuse?.hostnames)
      ? (profileAbuse.hostnames as unknown[])
          .filter((entry): entry is string => typeof entry === "string" && entry.trim() !== "")
          .map((value) => ({ value, source: "abuseipdb" as SourceId }))
      : []),
  ]);
  const techRows = mergeEntries(
    Array.isArray(profileIdb?.cpes)
      ? (profileIdb.cpes as unknown[])
          .filter((entry): entry is string => typeof entry === "string" && entry.trim() !== "")
          .map((cpe) => ({ value: cpeLabel(cpe) ?? cpe, source: "internetdb" as SourceId }))
      : [],
  );
  const profileVulns = Array.isArray(profileIdb?.vulns)
    ? (profileIdb.vulns as unknown[]).filter(
        (entry): entry is string => typeof entry === "string" && entry.trim() !== "",
      )
    : [];
  const isTor = typeof profileAbuse?.isTor === "boolean" ? profileAbuse.isTor : null;
  const hasProfileData =
    countryRows.length > 0 ||
    asnRows.length > 0 ||
    ispRows.length > 0 ||
    usageRows.length > 0 ||
    domainRows.length > 0 ||
    isTor !== null ||
    hostnameRows.length > 0 ||
    techRows.length > 0;
  const profileEmptyText = loading
    ? "Sorgulanıyor…"
    : analysisDone
      ? "Veri yok"
      : "Veri bekleniyor";

  const visibleContributions = contributionRows(displayScore, analysisDone);
  const location = resolveIpLocation(profileKind, countryRows, profileOtx);
  const primaryLocation = location.primary;
  const locationCoords = location.coordinates;
  const locationSources: SourceId[] = ["abuseipdb", "virustotal", "otx"];
  const locationSourcesFailed = locationSources.every((source) =>
    ["error", "rate_limited"].includes(profileResults[source]?.status ?? ""),
  );
  const locationMessage = !start
    ? "Analiz bekleniyor."
    : isDomainSearch && !dns?.selected
      ? dns
        ? "DNS'den genel IP adresi bulunamadı."
        : "DNS çözümlemesi bekleniyor."
      : loading
        ? "Konum kaynakları bekleniyor."
        : locationSourcesFailed
          ? "Konum kaynaklarına erişilemedi."
          : primaryLocation
            ? "Bu ülke için harita koordinatı bulunamadı."
            : "Konum verisi bulunamadı.";

  if (authenticated === null) {
    return (
      <div className="vesta-app">
        <main className="boot-screen">
          <LoaderCircle className="spin" />
        </main>
      </div>
    );
  }

  if (!authenticated) {
    return (
      <div className="vesta-app">
        <header className="topbar">
          <div className="topbar-inner">
            <div className="brand">
              <svg className="brand-shield" viewBox="0 0 32 38" aria-hidden="true">
                <path d="m16 1 5 6 10 2-3 16c-2 6-12 12-12 12S6 31 4 25L1 9l10-2Z" />
                <path d="m8 11 8 16 8-16" />
              </svg>
              <span className="brand-name">VESTA</span>
              <span className="brand-subtitle">Siber Tehdit İstihbaratı</span>
            </div>
          </div>
        </header>
        <main className="login-view">
          <section className="login-panel">
            <div className="login-brand">
              <svg className="brand-shield" viewBox="0 0 32 38" aria-hidden="true">
                <path d="m16 1 5 6 10 2-3 16c-2 6-12 12-12 12S6 31 4 25L1 9l10-2Z" />
                <path d="m8 11 8 16 8-16" />
              </svg>
            </div>
            <h1>Konsola giriş</h1>
            <p>Ortak parolayla yerel analiz oturumunu açın.</p>
            <form className="login-form" onSubmit={handleLogin}>
              <div className="login-field">
                <KeyRound />
                <input
                  type="password"
                  aria-label="Parola"
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(event) => {
                    setPassword(event.target.value);
                    setLoginError("");
                  }}
                  placeholder="Parola"
                />
              </div>
              <Button className="login-button" type="submit" disabled={loginBusy}>
                {loginBusy ? <LoaderCircle className="spin" /> : <LockKeyhole />}
                {loginBusy ? "Doğrulanıyor" : "Giriş yap"}
              </Button>
            </form>
            {loginError && (
              <p className="login-error" role="alert">
                {loginError}
              </p>
            )}
            <p className="login-footnote">
              <LockKeyhole />
              Sunucu yalnızca bu bilgisayardaki 127.0.0.1 adresinde dinler. API anahtarları
              tarayıcıya gönderilmez.
            </p>
          </section>
        </main>
        <footer className="footer">
          <div className="footer-left">
            <i className="status-dot" />
            <span>Yerel analiz konsolu</span>
          </div>
          <span>127.0.0.1 · Yerel panel</span>
        </footer>
      </div>
    );
  }

  return (
    <div className="vesta-app">
      <header className="topbar">
        <div className="topbar-inner">
          <div className="brand">
            <svg className="brand-shield" viewBox="0 0 32 38" aria-hidden="true">
              <path d="m16 1 5 6 10 2-3 16c-2 6-12 12-12 12S6 31 4 25L1 9l10-2Z" />
              <path d="m8 11 8 16 8-16" />
            </svg>
            <span className="brand-name">VESTA</span>
            <span className="brand-subtitle">Siber Tehdit İstihbaratı</span>
          </div>
          <div className="session">
            <span className="live-badge">
              <ShieldCheck size={14} />
              CANLI KAYNAKLAR
            </span>
            <span className="session-divider" />
            <div className="session-menu">
              <Button
                variant="ghost"
                className="text-muted-foreground px-1"
                aria-expanded={sessionOpen}
                onClick={() => setSessionOpen(!sessionOpen)}
              >
                <i className="status-dot" />
                Yerel oturum
                <ChevronDown />
              </Button>
              {sessionOpen && (
                <div className="session-popover">
                  <strong>Yerel oturum</strong>
                  <br />
                  Kimliği doğrulanmış oturum
                  <br />
                  <span className="connected-label">
                    <ShieldCheck size={15} /> Veriler bu oturuma özeldir
                  </span>
                  <Button
                    variant="secondary"
                    className="logout-button"
                    onClick={() => void handleLogout()}
                  >
                    <LogOut />
                    Oturumu kapat
                  </Button>
                </div>
              )}
            </div>
          </div>
        </div>
      </header>
      <main className="workspace">
        <nav className="primary-nav" aria-label="Ana menü">
          <span className="primary-nav-title">Çalışma alanı</span>
          <button
            type="button"
            className="primary-nav-item"
            aria-current={activeView === "analysis" ? "page" : undefined}
            onClick={() => setActiveView("analysis")}
          >
            <Search size={18} />
            <span>Analiz</span>
          </button>
          <button
            type="button"
            className="primary-nav-item"
            aria-current={activeView === "news" ? "page" : undefined}
            onClick={() => setActiveView("news")}
          >
            <Newspaper size={18} />
            <span>Haberler</span>
          </button>
        </nav>
        {activeView === "analysis" ? (
          <div className="workspace-content">
            <section className="intro">
              <form className="search-form" onSubmit={analyze}>
                <div className="search-field">
                  <Search />
                  <input
                    aria-label="IP adresi veya alan adı"
                    value={indicator}
                    onChange={(event) => {
                      setIndicator(event.target.value);
                      setError("");
                    }}
                    spellCheck={false}
                    placeholder="8.8.8.8 / example.com"
                  />
                </div>
                <Button className="analyze-button" type="submit" disabled={loading}>
                  {loading ? <LoaderCircle className="spin" /> : <Search />}
                  {loading ? "Analiz ediliyor" : "Analiz Et"}
                </Button>
              </form>
              {error && (
                <p className="input-error" role="alert">
                  {error}
                </p>
              )}
              <div className="usage-line">
                <div className="usage-items">
                  <span>
                    <Clock3 />
                    Son 24 saat: {usage?.searches_24h ?? "—"} arama
                  </span>
                  <span>
                    <ExternalLink />
                    VirusTotal{" "}
                    {usage
                      ? `${usage.virustotal_minute} / 4 dk · ${usage.virustotal_24h} / 500`
                      : "—"}
                  </span>
                  <span>
                    <Database />
                    AbuseIPDB {usage ? `${usage.abuseipdb_today_utc} / 1.000` : "—"}
                  </span>
                </div>
                <Button
                  variant="ghost"
                  className="usage-toggle"
                  aria-expanded={usageOpen}
                  onClick={() => setUsageOpen(!usageOpen)}
                >
                  Kullanım ayrıntıları
                  <ChevronDown className={usageOpen ? "rotate-180" : ""} />
                </Button>
              </div>
              {usageOpen && (
                <div className="usage-expanded">
                  <div className="usage-detail-grid">
                    {SOURCE_ORDER.map((source) => (
                      <span key={source}>
                        <strong>{SOURCE_NAMES[source]}</strong>
                        {usage?.requests_24h[source] ?? 0} istek / 24 sa
                      </span>
                    ))}
                  </div>
                  <p>
                    Bu bilgisayardan yapılan istekler sayılır. Başka uygulamaların aynı anahtarlarla
                    yaptığı istekler dahil değildir. AbuseIPDB sınırı ücretsiz hesap içindir; hesap
                    türünüz farklıysa değişebilir. Siber Güvenlik Başkanlığı sayfalama nedeniyle bir
                    aramada birden fazla HTTP isteği kullanabilir.
                  </p>
                </div>
              )}
            </section>
            <div className={`results-layout ${loading ? "analyzing" : ""}`} aria-busy={loading}>
              <div className="left-column">
                {isDomainSearch && (
                  <section className="dns-panel" aria-label="DNS çözümlemesi" role="status">
                    <div className="dns-heading">
                      <h2>Çözümlenen IP adresi</h2>
                    </div>
                    {!dns ? (
                      <p>DNS sorgusu sürüyor…</p>
                    ) : dns.status === "timeout" ? (
                      <p>DNS sorgusu zaman aşımına uğradı. Alan adı analizi devam etti.</p>
                    ) : dns.status === "error" ? (
                      <p>Alan adı DNS ile çözümlenemedi. Alan adı analizi devam etti.</p>
                    ) : dns.status === "no_public_ip" ? (
                      <>
                        {dns.addresses[0] && (
                          <div className="dns-addresses">
                            <span className="dns-address">{dns.addresses[0]}</span>
                          </div>
                        )}
                        <p>Bu adres özel veya yerel ağda; dış kaynaklarla IP analizi yapılmaz.</p>
                      </>
                    ) : (
                      <div className="dns-addresses">
                        <span className="dns-address selected">{dns.selected}</span>
                        <span className="dns-analysis-note">Bu IP otomatik analiz ediliyor.</span>
                      </div>
                    )}
                  </section>
                )}
                <section className="results-panel" aria-label="Kaynak sonuçları">
                  <div className="panel-heading">
                    <h2>
                      {isDomainSearch
                        ? activeScope === "ip"
                          ? `${dns?.selected ?? "IP"} kaynak sonuçları`
                          : "Alan adı kaynak sonuçları"
                        : "IP kaynak sonuçları"}
                    </h2>
                    <span className="response-badge">
                      {completed} / {sourceCount} yanıt
                    </span>
                    <div
                      className="response-track"
                      style={
                        {
                          "--track-width": `${(completed / sourceCount) * 100}%`,
                        } as React.CSSProperties
                      }
                    />
                  </div>
                  {isDomainSearch && dns?.selected && (
                    <div
                      className="analysis-scope-tabs"
                      role="group"
                      aria-label="Analiz edilen gösterge"
                    >
                      <button
                        type="button"
                        aria-pressed={activeScope === "domain"}
                        onClick={() => {
                          setActiveScope("domain");
                          setOpenSource(null);
                        }}
                      >
                        Alan adı · {start?.indicator}
                      </button>
                      <button
                        type="button"
                        aria-pressed={activeScope === "ip"}
                        onClick={() => {
                          setActiveScope("ip");
                          setOpenSource(null);
                        }}
                      >
                        Çözümlenen IP · {dns.selected}
                      </button>
                    </div>
                  )}
                  <div className="table-scroll">
                    <table className="source-table">
                      <thead>
                        <tr>
                          <th>Kaynak</th>
                          <th>Durum</th>
                          <th>Bulgu</th>
                          <th>Süre</th>
                          <th>Katkı</th>
                          <th aria-label="Ayrıntılar" />
                        </tr>
                      </thead>
                      {SOURCE_ORDER.map((source) => {
                        const item = displayResults[source];
                        const contribution = displayScore?.breakdown.find(
                          (entry) => entry.source === source,
                        )?.points;
                        const expanded = openSource === source && !loading;
                        return (
                          <tbody key={source}>
                            <tr onClick={() => !loading && setOpenSource(expanded ? null : source)}>
                              <td>
                                <span className="source-name">
                                  <SourceMark id={source} />
                                  {SOURCE_NAMES[source]}
                                </span>
                              </td>
                              <td>
                                {!item ? (
                                  <span className="status-badge status-empty">
                                    <LoaderCircle size={12} className="spin" />
                                    Bekleniyor
                                  </span>
                                ) : (
                                  <span className={`status-badge status-${item.status}`}>
                                    <i />
                                    {STATUS_LABELS[item.status]}
                                  </span>
                                )}
                              </td>
                              <td>{item ? item.summary : "Sorgulanıyor…"}</td>
                              <td>{item ? `${item.elapsed_ms} ms` : "—"}</td>
                              <td className={contribution ? "positive" : ""}>
                                {item && displayScore
                                  ? contribution === null
                                    ? "—"
                                    : `+${contribution}`
                                  : "—"}
                              </td>
                              <td>
                                <Button
                                  variant="ghost"
                                  className="expand-button"
                                  aria-label={`${SOURCE_NAMES[source]} ayrıntıları`}
                                  aria-expanded={expanded}
                                  disabled={loading}
                                >
                                  {expanded ? <ChevronDown /> : <ChevronRight />}
                                </Button>
                              </td>
                            </tr>
                            {expanded && item && (
                              <tr className="detail-row">
                                <td colSpan={6}>
                                  <div className="source-detail">
                                    <div className="detail-heading">
                                      <span>
                                        <SourceMark id={source} />
                                        <span>
                                          <strong>{SOURCE_NAMES[source]}</strong> detayları
                                        </span>
                                      </span>
                                      <span className="detail-actions">
                                        <Button
                                          variant="secondary"
                                          className="json-button"
                                          onClick={() => {
                                            setJsonSource(item);
                                            setCopied(false);
                                          }}
                                        >
                                          <Braces />
                                          JSON ayrıntıları
                                        </Button>
                                        {item.link && (
                                          <a
                                            className="external-button"
                                            href={item.link}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            aria-label={`${SOURCE_NAMES[source]} kaynağını aç`}
                                          >
                                            <ExternalLink />
                                            Kaynağı aç
                                          </a>
                                        )}
                                      </span>
                                    </div>
                                    {source === "internetdb" && item.details ? (
                                      <>
                                        <div className="shodan-metrics">
                                          <div className="metric">
                                            <label>
                                              Açık portlar (
                                              {String(item.details.ports?.length ?? 0)})
                                            </label>
                                            <div className="ports">
                                              {Array.isArray(item.details.ports) &&
                                              item.details.ports.length ? (
                                                item.details.ports.map((port: number) => (
                                                  <span key={port}>{port}</span>
                                                ))
                                              ) : (
                                                <span className="muted-port">Kayıt yok</span>
                                              )}
                                            </div>
                                          </div>
                                          <div className="metric">
                                            <label>Hostname</label>
                                            <strong>
                                              {String(item.details.hostnames?.length ?? 0)}
                                            </strong>
                                          </div>
                                          <div className="metric">
                                            <label>CPE</label>
                                            <strong>
                                              {String(item.details.cpes?.length ?? 0)}
                                            </strong>
                                          </div>
                                          <div className="metric">
                                            <label>Olası zafiyet</label>
                                            <strong>
                                              {String(item.details.vulns?.length ?? 0)}
                                            </strong>
                                          </div>
                                        </div>
                                        {Array.isArray(item.details.vulns) &&
                                          item.details.vulns.length > 0 && (
                                            <div className="vulns">
                                              <span className="vuln-label">OLASI ZAFİYETLER</span>
                                              {item.details.vulns.map((vuln: string) => {
                                                const link = cveLink(vuln);
                                                return link ? (
                                                  <a
                                                    className="vuln"
                                                    key={vuln}
                                                    href={link}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    aria-label={`${vuln} kaydını NVD'de aç`}
                                                  >
                                                    {vuln}
                                                  </a>
                                                ) : (
                                                  <span className="vuln" key={vuln}>
                                                    {vuln}
                                                  </span>
                                                );
                                              })}
                                            </div>
                                          )}
                                      </>
                                    ) : (
                                      <p className="source-description">{item.summary}</p>
                                    )}
                                  </div>
                                </td>
                              </tr>
                            )}
                          </tbody>
                        );
                      })}
                    </table>
                  </div>
                </section>
                <section
                  className="profile-panel"
                  aria-label="IP Teknik Profili"
                  aria-busy={loading}
                >
                  <div className="profile-heading">
                    <h2>IP Teknik Profili</h2>
                    {dns?.selected && <span className="response-badge">{dns.selected}</span>}
                    <p>
                      {!start && !loading
                        ? "Analiz yapıldığında IP adresine ait teknik profil burada görüntülenecek."
                        : loading && !hasProfileData
                          ? "Teknik profil kaynakları sorgulanıyor."
                          : "Birden fazla istihbarat kaynağından elde edilen ağ ve altyapı bilgileri."}
                    </p>
                  </div>
                  <div className="profile-grid">
                    <ProfileField label="Ülke" icon={<MapPin size={13} />}>
                      {countryRows.length ? (
                        countryRows.map((row) => (
                          <div className="profile-row" key={`${row.code}:${row.sources.join(",")}`}>
                            <span className="profile-text">
                              {flagEmoji(row.code) && `${flagEmoji(row.code)} `}
                              {row.name ?? row.code}
                            </span>
                            <SourceTags sources={row.sources} />
                          </div>
                        ))
                      ) : (
                        <span className="profile-none">{profileEmptyText}</span>
                      )}
                    </ProfileField>
                    <ProfileField label="İnternet Sağlayıcısı (ISP)" icon={<Building2 size={13} />}>
                      <ProfileRows rows={ispRows} emptyLabel={profileEmptyText} />
                    </ProfileField>
                    <ProfileField label="ASN" icon={<Router size={13} />}>
                      <ProfileRows rows={asnRows} emptyLabel={profileEmptyText} />
                    </ProfileField>
                    <ProfileField label="Kullanım Türü" icon={<Server size={13} />}>
                      <ProfileRows rows={usageRows} emptyLabel={profileEmptyText} />
                    </ProfileField>
                    <ProfileField label="İlişkili Alan Adı" icon={<Globe size={13} />}>
                      <ProfileRows rows={domainRows} emptyLabel={profileEmptyText} />
                    </ProfileField>
                    <ProfileField label="Tor Durumu" icon={<Shield size={13} />}>
                      {isTor === null ? (
                        <span className="profile-none">{profileEmptyText}</span>
                      ) : (
                        <div className="profile-row">
                          <span className="profile-text">
                            {isTor ? "Tor çıkış noktası" : "Tor çıkış noktası değil"}
                          </span>
                          <SourceTags sources={["abuseipdb"]} />
                        </div>
                      )}
                    </ProfileField>
                  </div>
                  <div className="profile-sections">
                    <div className="profile-section">
                      <label>
                        <Server size={13} />
                        Hostname'ler
                      </label>
                      <ProfileChips rows={hostnameRows} emptyLabel={profileEmptyText} />
                    </div>
                    <div className="profile-section">
                      <label>
                        <Cpu size={13} />
                        Tespit Edilen Teknolojiler
                      </label>
                      <ProfileChips rows={techRows} emptyLabel={profileEmptyText} />
                    </div>
                  </div>
                </section>
              </div>
              <aside className="side-column">
                <div className="side-overview">
                  <section className="risk-panel">
                    <div className="side-heading">
                      <h2>
                        {isDomainSearch && activeScope === "domain"
                          ? "Alan adı risk puanı"
                          : "IP risk puanı"}
                      </h2>
                      {displayScore?.value === null || !displayScore ? (
                        <span className="live-badge">
                          <Info size={12} />
                          Bekleniyor
                        </span>
                      ) : displayScore.provisional ? (
                        <span className="demo-badge">
                          <Info size={12} />
                          Ön sonuç
                        </span>
                      ) : (
                        <span className="live-badge">
                          <Info size={12} />
                          Tamamlandı
                        </span>
                      )}
                    </div>
                    <div className="risk-content">
                      <div
                        className="risk-gauge"
                        role="img"
                        aria-label={`${!isDomainSearch || activeScope === "ip" ? "IP" : "Alan adı"} risk puanı: ${displayScore?.value ?? "—"} / 100`}
                      >
                        <svg viewBox="0 0 120 120">
                          <circle className="gauge-track" cx="60" cy="60" r="52" />
                          <circle
                            className="gauge-value"
                            cx="60"
                            cy="60"
                            r="52"
                            style={{
                              strokeDasharray: `${((displayScore?.value ?? 0) / 100) * GAUGE_CIRCUMFERENCE} ${GAUGE_CIRCUMFERENCE}`,
                            }}
                          />
                        </svg>
                        <div className="gauge-label">
                          <strong>{displayScore?.value ?? "—"}</strong>
                          <span>/ 100</span>
                        </div>
                      </div>
                      <div className="risk-note">
                        {!displayScore ? (
                          "Analiz bekleniyor."
                        ) : displayScore.value === null ? (
                          "Kaynak sonuçları bekleniyor."
                        ) : displayScore.provisional ? (
                          <>
                            Bazı kaynaklar yanıtlamadı.
                            <br />
                            Puan güncellenebilir.
                          </>
                        ) : (
                          "Tüm uygun kaynaklar değerlendirildi."
                        )}
                      </div>
                    </div>
                  </section>
                  <section className="contribution-panel">
                    <h2>Kaynak katkıları</h2>
                    {analysisDone && visibleContributions.length === 0 ? (
                      <p className="contribution-empty">
                        Risk puanına katkı sağlayan kaynak bulunamadı.
                      </p>
                    ) : (
                      <div className="contributions">
                        {visibleContributions.map(({ source, points, max }) => {
                          const width =
                            points > 0 && max > 0 ? Math.min(100, (points / max) * 100) : 0;
                          return (
                            <div className="contribution" key={source}>
                              <span>
                                {source === "internetdb"
                                  ? "InternetDB"
                                  : source === "sgb"
                                    ? "SGB"
                                    : source === "otx"
                                      ? "OTX"
                                      : source === "abuseipdb"
                                        ? "AbuseIPDB"
                                        : source === "threatfox"
                                          ? "ThreatFox"
                                          : SOURCE_NAMES[source]}
                              </span>
                              <div className={`contribution-track ${points === 0 ? "empty" : ""}`}>
                                <i
                                  style={points > 0 ? { width: `${width}%` } : { display: "none" }}
                                />
                              </div>
                              <span>{points}</span>
                            </div>
                          );
                        })}
                      </div>
                    )}
                    <p className="contribution-note">
                      <Info />
                      Açık port sayısı puanı artırmaz.
                    </p>
                  </section>
                </div>
                <div className="side-lower">
                  <section className="port-panel">
                    <div className="port-heading">
                      <h2>Açık Portlar</h2>
                      {dns?.selected && <span className="response-badge">{dns.selected}</span>}
                      {internetdbResult &&
                        (internetdbResult.status === "match" ||
                          internetdbResult.status === "no_match") && (
                          <span className="response-badge">{internetPorts.length} port</span>
                        )}
                    </div>
                    {internetdbResult &&
                    internetdbResult.status === "match" &&
                    internetPorts.length > 0 ? (
                      <table className="port-table">
                        <thead>
                          <tr>
                            <th>Port</th>
                            <th>Servis</th>
                            <th>Durum</th>
                          </tr>
                        </thead>
                        <tbody>
                          {internetPorts.map((port) => (
                            <tr key={port}>
                              <td className="port-num">
                                <a
                                  className="port-link"
                                  href={`https://www.google.com/search?q=port+${port}`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  aria-label={`${port} portunu Google'da ara`}
                                  title="Google'da ara"
                                >
                                  {port}
                                </a>
                              </td>
                              <td className="port-svc">{portService(port)}</td>
                              <td>
                                <span className="port-status">Gözlemlendi</span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    ) : (
                      <p className="port-empty">{portMessage}</p>
                    )}
                    {profileVulns.length > 0 && (
                      <div className="vulns">
                        <span className="vuln-label">OLASI ZAFİYETLER</span>
                        {profileVulns.map((vuln) => {
                          const link = cveLink(vuln);
                          return link ? (
                            <a
                              className="vuln"
                              key={vuln}
                              href={link}
                              target="_blank"
                              rel="noopener noreferrer"
                              aria-label={`${vuln} kaydını NVD'de aç`}
                            >
                              {vuln}
                            </a>
                          ) : (
                            <span className="vuln" key={vuln}>
                              {vuln}
                            </span>
                          );
                        })}
                      </div>
                    )}
                  </section>
                  <section className="location-panel" aria-label="IP Coğrafi Konumu">
                    <div className="port-heading">
                      <h2>IP Coğrafi Konumu</h2>
                      {dns?.selected && <span className="response-badge">{dns.selected}</span>}
                      {primaryLocation && (
                        <span className="response-badge">
                          {flagEmoji(primaryLocation.code)} {primaryLocation.code}
                        </span>
                      )}
                    </div>
                    {locationCoords ? (
                      <LocationMap
                        key={`${dns?.selected ?? start?.indicator}:${locationCoords[0]}:${locationCoords[1]}`}
                        lat={locationCoords[0]}
                        lng={locationCoords[1]}
                      />
                    ) : (
                      <p className="port-empty">{locationMessage}</p>
                    )}
                    {primaryLocation && (
                      <div className="location-meta">
                        <div className="location-line">
                          <span className="profile-text">
                            {flagEmoji(primaryLocation.code)} {displayCountry(primaryLocation)} ·{" "}
                            {primaryLocation.code}
                            {location.city && ` · ${location.city}`}
                          </span>
                          <SourceTags sources={primaryLocation.sources} />
                        </div>
                        {location.alternatives.length > 0 && (
                          <div className="location-warning" role="status">
                            Kaynaklar arasında konum farklılığı var
                            {location.alternatives.map((row) => (
                              <span className="location-alt" key={row.code}>
                                {flagEmoji(row.code)} {displayCountry(row)} · {row.code}
                                <SourceTags sources={row.sources} />
                              </span>
                            ))}
                          </div>
                        )}
                        {location.coordinateSource && (
                          <p className="location-note">
                            {location.coordinateSource === "country"
                              ? "Yaklaşık ülke konumu. İşaretçi ülke merkezindedir; IP'nin kesin fiziksel konumu değildir."
                              : "OTX tarafından bildirilen yaklaşık IP konumu; kesin fiziksel konum değildir."}
                          </p>
                        )}
                      </div>
                    )}
                  </section>
                </div>
              </aside>
            </div>
          </div>
        ) : (
          <NewsView
            data={news}
            loading={newsLoading}
            error={newsError}
            query={newsQuery}
            onQueryChange={setNewsQuery}
            onAnalyze={(value) => {
              setIndicator(value);
              setActiveView("analysis");
              window.scrollTo({ top: 0, behavior: "smooth" });
            }}
            onRefresh={() => {
              newsFreshRef.current = true;
              setNewsRefreshKey((key) => key + 1);
            }}
          />
        )}
      </main>
      <footer className={activeView === "news" ? "footer" : "footer footer-soc"}>
        <div className="footer-left">
          <i className="status-dot" />
          <span>{SOURCE_ORDER.length} bağlı kaynak</span>
          <span className="security">
            <LockKeyhole />
            API anahtarları sunucuda saklanır
          </span>
        </div>
        {activeView === "analysis" && (
          <SocTicker items={news?.items ?? []} loading={newsLoading} error={newsError} />
        )}
        <span>127.0.0.1 · Yerel panel</span>
      </footer>
      {jsonSource && (
        <div className="json-overlay" onClick={() => setJsonSource(null)}>
          <section
            className="json-dialog"
            role="dialog"
            aria-modal="true"
            aria-label="JSON ayrıntıları"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="json-header">
              <h2>{SOURCE_NAMES[jsonSource.source]} · JSON ayrıntıları</h2>
              <Button
                variant="ghost"
                size="icon"
                aria-label="Kapat"
                autoFocus
                onClick={() => setJsonSource(null)}
              >
                <X />
              </Button>
            </div>
            <pre>{json}</pre>
            <Button
              variant="secondary"
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(json);
                  setCopied(true);
                } catch {
                  setCopied(false);
                }
              }}
            >
              {copied ? <Check /> : <Copy />}
              {copied ? "Kopyalandı" : "JSON kopyala"}
            </Button>
          </section>
        </div>
      )}
    </div>
  );
}
