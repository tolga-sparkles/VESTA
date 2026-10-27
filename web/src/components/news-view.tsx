import { useEffect, useState } from "react";
import { ArrowRight, ExternalLink, LoaderCircle, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import type {
  NewsCategory,
  NewsEvent,
  NewsItem,
  NewsQuery,
  NewsSnapshot,
  TweetItem,
} from "@/lib/vesta-data";

type NewsFilter = "all" | "x" | NewsCategory;
const FILTERS: { id: NewsFilter; label: string }[] = [
  { id: "all", label: "Genel bakış" },
  { id: "news", label: "Haberler" },
  { id: "official", label: "Resmî" },
  { id: "privacy", label: "KVKK" },
  { id: "cve", label: "CVE" },
  { id: "ioc", label: "IOC" },
  { id: "x", label: "X" },
];
const CATEGORY_NAMES: Record<NewsCategory, string> = {
  news: "Haber",
  official: "Resmî",
  privacy: "İhlal",
  cve: "CVE",
  ioc: "IOC",
};
const PRIORITY_NAMES: Record<string, string> = {
  critical: "Kritik öncelik",
  high: "Yüksek öncelik",
  medium: "Orta öncelik",
  low: "Düşük öncelik",
  general: "Genel teknik içerik",
};
const VERIFICATION_NAMES: Record<string, string> = {
  official_publication: "Resmî yayın",
  supported: "Bağımsız kaynaklarla destekli",
  single_source: "Tek kaynak bildirimi",
  unverified_claim: "Doğrulanmamış iddia",
  conflicting: "Çelişkili bilgiler",
  unevaluated: "Değerlendirilemedi",
};
const CONTENT_NAMES: Record<string, string> = {
  cyber_news: "Siber güvenlik haberi",
  incident_report: "Saldırı / olay",
  breach_notice: "Veri ihlali",
  vulnerability: "Güvenlik açığı",
  threat_research: "Tehdit araştırması",
  technical_guide: "Teknik rehber",
  general_technology: "Genel teknoloji",
  ioc: "IOC veri kaydı",
  official_notice: "Resmî bildirim",
};
const HEALTH_NAMES: Record<string, string> = {
  working: "Çalışıyor",
  delayed: "Gecikmeli",
  stale: "Eski veri",
  unreachable: "Erişilemiyor",
  parse_error: "Ayrıştırma hatası",
  unchecked: "Henüz kontrol edilmedi",
};
const DATE_FORMATTER = new Intl.DateTimeFormat("tr-TR", {
  day: "numeric",
  month: "short",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
});
const DAY_FORMATTER = new Intl.DateTimeFormat("tr-TR", {
  day: "numeric",
  month: "short",
  year: "numeric",
  timeZone: "UTC",
});

function formatDate(value: string | null, dateOnly = false): string {
  if (!value) return "Tarih yok";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "Tarih yok"
    : dateOnly
      ? DAY_FORMATTER.format(date)
      : DATE_FORMATTER.format(date);
}

function extractIndicator(title: string): string | null {
  const first = title.split(/\s+/)[0] ?? "";
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(first)) return first;
  if (/^[a-f0-9:]+$/i.test(first) && first.includes(":")) return first;
  if (/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.(?:[a-z0-9-]*[a-z0-9])?$/i.test(first)) return first;
  return null;
}

const COMPACT_COUNT = new Intl.NumberFormat("tr-TR", {
  notation: "compact",
  maximumFractionDigits: 1,
});

function formatCount(value: number): string {
  return COMPACT_COUNT.format(value);
}

function TweetCard({
  tweet,
  relatedCount = 1,
  linkedEvent,
}: {
  tweet: TweetItem;
  relatedCount?: number | undefined;
  linkedEvent?: NewsEvent | undefined;
}) {
  const [expanded, setExpanded] = useState(false);
  const [imageOpen, setImageOpen] = useState(false);
  const images = (tweet.media ?? []).filter(
    (media) => media.type === "photo" && (media.local || media.url),
  );
  const xUrl = `https://x.com/${tweet.username}/status/${tweet.id}`;
  return (
    <article className="tweet-card">
      <div className="tweet-head">
        <span className="tweet-avatar" aria-hidden="true">
          {(tweet.name?.[0] ?? tweet.username[0] ?? "?").toUpperCase()}
        </span>
        <div className="tweet-identity">
          <strong>{tweet.name || tweet.username}</strong>
          <span>@{tweet.username}</span>
        </div>
        <time dateTime={tweet.created_at ?? undefined}>{formatDate(tweet.created_at)}</time>
      </div>
      <span className="tweet-claim">
        {tweet.evaluation?.label ?? "Doğrulanmamış sosyal medya bildirimi"}
      </span>
      {tweet.evaluation && (
        <small className="tweet-claim-context">
          İddia türü:{" "}
          {tweet.evaluation.claim_type === "ddos"
            ? "DDoS"
            : tweet.evaluation.claim_type === "breach"
              ? "Veri ihlali"
              : tweet.evaluation.claim_type === "phishing"
                ? "Oltalama"
                : "Güvenlik bildirimi"}{" "}
          · Hesap kimliği bağımsız doğrulanmadı
        </small>
      )}
      {linkedEvent?.sources[0] && (
        <a
          className="tweet-related"
          href={linkedEvent.sources[0].url}
          target="_blank"
          rel="noopener noreferrer"
        >
          İlişkili haber: {linkedEvent.title}
        </a>
      )}
      {relatedCount > 1 && <small>Aynı olay hakkında {relatedCount} paylaşım</small>}
      <p className={`tweet-text ${expanded ? "expanded" : ""}`}>{tweet.text}</p>
      {tweet.text.length > 170 && (
        <button className="news-text-button" type="button" onClick={() => setExpanded(!expanded)}>
          {expanded ? "Daralt" : "Tamamını göster"}
        </button>
      )}
      {images.length > 0 && (
        <button
          className="tweet-thumbnail"
          type="button"
          onClick={() => setImageOpen(true)}
          aria-label="Gönderi görselini büyüt"
        >
          <img
            src={images[0]?.local ?? images[0]?.url ?? ""}
            alt="Gönderi görseli önizlemesi"
            loading="lazy"
          />
          {images.length > 1 && <span>+{images.length - 1} görsel</span>}
        </button>
      )}
      {imageOpen && (
        <div
          className="tweet-lightbox"
          role="dialog"
          aria-modal="true"
          aria-label="Gönderi görseli"
          onClick={() => setImageOpen(false)}
        >
          <button type="button" onClick={() => setImageOpen(false)}>
            Kapat ×
          </button>
          <img src={images[0]?.local ?? images[0]?.url ?? ""} alt="Gönderi görseli" />
        </div>
      )}
      <div className="tweet-stats">
        <span title="Beğeni">♥ {formatCount(tweet.favorite_count)}</span>
        <span title="Yeniden paylaşım">↻ {formatCount(tweet.retweet_count)}</span>
        <span title="Yanıt">💬 {formatCount(tweet.reply_count)}</span>
        <span title="Görüntülenme">👁 {formatCount(tweet.view_count)}</span>
        <a
          className="tweet-link"
          href={xUrl}
          target="_blank"
          rel="noopener noreferrer"
          aria-label={`@${tweet.username} gönderisini X'te aç`}
        >
          Gönderiye git <ExternalLink size={13} aria-hidden="true" />
        </a>
      </div>
    </article>
  );
}

function NewsCard({
  item,
  featured = false,
  onAnalyze,
  event,
}: {
  item: NewsItem;
  featured?: boolean;
  onAnalyze?: ((value: string) => void) | undefined;
  event?: NewsEvent | undefined;
}) {
  const indicator = item.category === "ioc" ? extractIndicator(item.title) : null;
  const rest = indicator
    ? item.title.slice(indicator.length).trim()
    : item.category === "privacy"
      ? item.title.replace(/^Kamuoyu Duyurusu\s*\(Veri İhlali Bildirimi\)\s*[–-]\s*/i, "")
      : item.title;
  return (
    <article className={`news-card ${featured ? "news-card-featured" : ""}`}>
      <div className="news-card-meta">
        <span className={`news-category news-category-${item.category}`}>
          {CATEGORY_NAMES[item.category]}
        </span>
        <span>{item.source}</span>
        <time
          dateTime={
            item.category === "cve"
              ? (item.cve_data?.published_at ?? undefined)
              : (item.published_at ?? undefined)
          }
        >
          {item.category === "cve"
            ? `İlk yayın: ${formatDate(item.cve_data?.published_at ?? null, true)}`
            : formatDate(item.published_at, item.date_only)}
        </time>
      </div>
      {item.evaluation && (
        <div className="news-evaluation">
          <span className={`news-priority priority-${item.evaluation.priority}`}>
            {PRIORITY_NAMES[item.evaluation.priority]}
          </span>
          <span className="news-verification">
            {VERIFICATION_NAMES[item.evaluation.verification] ?? item.evaluation.verification}
          </span>
          {item.evaluation.source_count > 1 && <span>{item.evaluation.source_count} kaynak</span>}
        </div>
      )}
      <h3>
        <a href={item.url} target="_blank" rel="noopener noreferrer" aria-label={item.title}>
          {indicator && <span className="news-indicator">{indicator}</span>}
          <span>{rest}</span>
          <ExternalLink size={15} aria-hidden="true" />
        </a>
      </h3>
      {item.summary && <p className="news-card-summary">{item.summary}</p>}
      {item.evaluation && (
        <p className="news-card-evidence">
          {CONTENT_NAMES[item.evaluation.content_type] ?? item.evaluation.content_type} ·{" "}
          {item.evaluation.indicators.cves.length} CVE ·{" "}
          {item.evaluation.indicators.ips.length + item.evaluation.indicators.domains.length} IOC
          {item.evaluation.active_exploitation ? " · CISA KEV eşleşmesi" : ""}
        </p>
      )}
      {item.cve_data && (
        <p className="news-card-evidence">
          İlk yayın {formatDate(item.cve_data.published_at, true)} · RSS kaydı{" "}
          {formatDate(item.cve_data.rss_added_at, true)}
          {item.cve_data.cvss
            ? ` · CVSS ${item.cve_data.cvss.score} (${item.cve_data.cvss.version})`
            : ""}
          {item.cve_data.kev === null ? " · KEV durumu bilinmiyor" : ""}
        </p>
      )}
      {item.evaluation?.reasons.length ? (
        <details className="news-evidence-details">
          <summary>Değerlendirme gerekçesi</summary>
          <ul>
            {item.evaluation.reasons.map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ul>
          <small>
            Sıralama bileşenleri:{" "}
            {Object.entries(item.evaluation.rank_components)
              .map(([key, value]) => `${key} ${value}`)
              .join(" · ")}
          </small>
        </details>
      ) : null}
      {event && event.item_ids.length > 1 && (
        <details className="news-evidence-details">
          <summary>
            {event.item_ids.length} ilişkili haber · {event.independent_source_count} bağımsız
            kaynak
          </summary>
          <ol>
            {event.timeline.map((entry) => (
              <li key={entry.item_id}>
                <time>{formatDate(entry.published_at)}</time>{" "}
                <a href={entry.url} target="_blank" rel="noopener noreferrer">
                  {entry.title}
                </a>
              </li>
            ))}
          </ol>
        </details>
      )}
      {onAnalyze &&
      (item.evaluation?.indicators.ips.length ||
        item.evaluation?.indicators.domains.length ||
        indicator) ? (
        <div className="news-analyze-actions">
          {[
            ...(item.evaluation?.indicators.ips ?? []),
            ...(item.evaluation?.indicators.domains ?? []),
          ]
            .slice(0, 2)
            .map((value) => (
              <button key={value} type="button" onClick={() => onAnalyze(value)}>
                VESTA'da Analiz Et: {value}
              </button>
            ))}
          {!item.evaluation && indicator && (
            <button type="button" onClick={() => onAnalyze(indicator)}>
              VESTA'da Analiz Et: {indicator}
            </button>
          )}
        </div>
      ) : null}
    </article>
  );
}

export function NewsView({
  data,
  loading,
  error,
  onRefresh,
  query = {},
  onQueryChange,
  onAnalyze,
}: {
  data: NewsSnapshot | null;
  loading: boolean;
  error: string;
  onRefresh: () => void;
  query?: NewsQuery;
  onQueryChange?: (query: NewsQuery) => void;
  onAnalyze?: (value: string) => void;
}) {
  const [filter, setFilter] = useState<NewsFilter>("all");
  const [visibleCount, setVisibleCount] = useState(20);
  const [search, setSearch] = useState(query.q ?? "");
  useEffect(() => {
    if (!onQueryChange || search === (query.q ?? "")) return;
    const timer = window.setTimeout(() => onQueryChange({ ...query, q: search, page: "1" }), 300);
    return () => window.clearTimeout(timer);
  }, [search, query, onQueryChange]);
  const allItems = data?.items ?? [];
  const tweets = data?.tweets?.tweets ?? [];
  const tweetAccounts = data?.tweets?.accounts ?? [];
  const byCategory: Record<NewsCategory, NewsItem[]> = {
    news: [],
    official: [],
    privacy: [],
    cve: [],
    ioc: [],
  };
  for (const item of allItems) byCategory[item.category].push(item);
  const eventByItem = new Map(
    (data?.events ?? []).flatMap((event) => event.item_ids.map((id) => [id, event] as const)),
  );
  const shownEvents = new Set<string>();
  const representativeItems = allItems.filter((item) => {
    if (!item.event_id) return true;
    const group = `${item.category}:${item.event_id}`;
    if (shownEvents.has(group)) return false;
    shownEvents.add(group);
    return true;
  });
  const displayByCategory: Record<NewsCategory, NewsItem[]> = {
    news: [],
    official: [],
    privacy: [],
    cve: [],
    ioc: [],
  };
  for (const item of representativeItems) displayByCategory[item.category].push(item);
  const spotlightNews = representativeItems
    .filter(
      (item) =>
        item.category === "news" &&
        item.evaluation?.content_type !== "technical_guide" &&
        item.evaluation?.content_type !== "general_technology",
    )
    .slice(0, 3);
  const tweetGroups = new Map<string, number>();
  for (const tweet of tweets)
    tweetGroups.set(
      tweet.group_id ?? tweet.id,
      (tweetGroups.get(tweet.group_id ?? tweet.id) ?? 0) + 1,
    );
  const groupedTweets = tweets.filter(
    (tweet, index) =>
      tweets.findIndex((other) => (other.group_id ?? other.id) === (tweet.group_id ?? tweet.id)) ===
      index,
  );
  const radarNew = (data?.cve_radar?.new ?? [])
    .map((id) => allItems.find((item) => item.id === id))
    .filter((item): item is NewsItem => !!item);
  const radarKev = (data?.cve_radar?.known_exploited ?? [])
    .map((id) => allItems.find((item) => item.id === id))
    .filter((item): item is NewsItem => !!item);
  const items =
    filter === "all" || filter === "x" ? representativeItems : displayByCategory[filter];
  const filterCounts: Record<NewsFilter, number> = {
    all: allItems.length,
    x: tweets.length,
    news: byCategory.news.length,
    official: byCategory.official.length,
    privacy: byCategory.privacy.length,
    cve: byCategory.cve.length,
    ioc: byCategory.ioc.length,
  };
  const okSources = data?.sources.filter((source) => source.status === "ok").length ?? 0;
  const totalSources = data?.sources.length ?? 0;
  const failedSources = totalSources - okSources;
  function selectFilter(next: NewsFilter) {
    setFilter(next);
    setVisibleCount(20);
  }

  return (
    <section className="news-view" aria-labelledby="news-title">
      <div className="news-header">
        <div>
          <span className="news-eyebrow">VESTA / GÜVENLİK GÜNDEMİ</span>
          <h1 id="news-title">Tehdit akışı</h1>
          <p>Güncel haberler, zafiyetler ve tehdit göstergeleri bir arada.</p>
        </div>
        <Button variant="secondary" onClick={onRefresh} disabled={loading}>
          {loading ? <LoaderCircle className="spin" /> : <RefreshCw />} Yenile
        </Button>
      </div>

      <div className="news-toolbar">
        <div className="news-filters" role="group" aria-label="İçerik türü">
          {FILTERS.map((option) => (
            <button
              key={option.id}
              type="button"
              aria-pressed={filter === option.id}
              onClick={() => selectFilter(option.id)}
            >
              {option.label}
              {data && option.id !== "all" && (
                <span className="news-filter-count">{filterCounts[option.id]}</span>
              )}
            </button>
          ))}
        </div>
        {data && (
          <div className="news-toolbar-meta">
            <span className={`news-source-summary ${failedSources ? "warn" : "ok"}`} role="status">
              {okSources}/{totalSources} kaynak
            </span>
            <span className="news-updated">Güncelleme {formatDate(data.fetched_at)}</span>
          </div>
        )}
      </div>
      <div className="news-search-panel" aria-label="Haber arama ve filtreleme">
        <input
          aria-label="Haber, CVE, IP, domain veya kurum ara"
          placeholder="Haber, CVE, IP, domain veya kurum ara…"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />
        <select
          aria-label="Sıralama"
          value={query.sort ?? "recommended"}
          onChange={(event) => onQueryChange?.({ ...query, sort: event.target.value, page: "1" })}
        >
          <option value="recommended">Önerilen</option>
          <option value="newest">En yeni</option>
          <option value="critical">Kritik öncelik</option>
          <option value="official">Resmî kaynaklar</option>
        </select>
        <details className="news-advanced-filters">
          <summary>Gelişmiş filtreler</summary>
          <div className="news-filter-fields">
            <label>
              Kaynak
              <select
                value={query.source ?? ""}
                onChange={(event) =>
                  onQueryChange?.({ ...query, source: event.target.value, page: "1" })
                }
              >
                <option value="">Tümü</option>
                {data?.sources.map((source) => (
                  <option key={source.id} value={source.id}>
                    {source.name}
                  </option>
                ))}
              </select>
            </label>
            <label>
              İçerik türü
              <select
                value={query.content_type ?? ""}
                onChange={(event) =>
                  onQueryChange?.({ ...query, content_type: event.target.value, page: "1" })
                }
              >
                <option value="">Tümü</option>
                {Object.entries(CONTENT_NAMES).map(([value, name]) => (
                  <option key={value} value={value}>
                    {name}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Öncelik
              <select
                value={query.priority ?? ""}
                onChange={(event) =>
                  onQueryChange?.({ ...query, priority: event.target.value, page: "1" })
                }
              >
                <option value="">Tümü</option>
                {Object.entries(PRIORITY_NAMES).map(([value, name]) => (
                  <option key={value} value={value}>
                    {name}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Doğrulama
              <select
                value={query.verification ?? ""}
                onChange={(event) =>
                  onQueryChange?.({ ...query, verification: event.target.value, page: "1" })
                }
              >
                <option value="">Tümü</option>
                {Object.entries(VERIFICATION_NAMES).map(([value, name]) => (
                  <option key={value} value={value}>
                    {name}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Bölge
              <select
                value={query.region ?? ""}
                onChange={(event) =>
                  onQueryChange?.({ ...query, region: event.target.value, page: "1" })
                }
              >
                <option value="">Tümü</option>
                <option value="turkey">Türkiye</option>
                <option value="global">Global</option>
                <option value="unknown">Belirsiz</option>
              </select>
            </label>
            <label>
              Aktif istismar
              <select
                value={query.active_exploitation ?? ""}
                onChange={(event) =>
                  onQueryChange?.({ ...query, active_exploitation: event.target.value, page: "1" })
                }
              >
                <option value="">Tümü</option>
                <option value="true">Kanıt var</option>
                <option value="false">Kanıt yok / bilinmiyor</option>
              </select>
            </label>
            <label>
              Başlangıç
              <input
                type="date"
                value={query.from_date ?? ""}
                onChange={(event) =>
                  onQueryChange?.({ ...query, from_date: event.target.value, page: "1" })
                }
              />
            </label>
            <label>
              Bitiş
              <input
                type="date"
                value={query.to_date ?? ""}
                onChange={(event) =>
                  onQueryChange?.({ ...query, to_date: event.target.value, page: "1" })
                }
              />
            </label>
            <button
              type="button"
              onClick={() => {
                setSearch("");
                onQueryChange?.({});
              }}
            >
              Filtreleri temizle
            </button>
          </div>
        </details>
      </div>

      {data?.stale && (
        <p className="news-stale" role="status">
          Akışlara şu an ulaşılamıyor; son başarılı kayıtlar gösteriliyor.
        </p>
      )}
      {error && (
        <p className="news-error" role="alert">
          {error}
        </p>
      )}

      {loading && !data ? (
        <div className="news-loading" role="status" aria-live="polite">
          <div className="news-loading-status">
            <LoaderCircle className="spin" size={18} aria-hidden="true" />
            Haberler ve resmî bildirimler yükleniyor…
          </div>
          <div className="news-loading-grid" aria-hidden="true">
            {[
              "Son haberler",
              "Siber Güvenlik Başkanlığı",
              "KVKK veri ihlalleri",
              "CVE ve IOC kayıtları",
            ].map((title) => (
              <div className="news-loading-panel" key={title}>
                <strong>{title}</strong>
                <span className="news-loading-line" />
                <span className="news-loading-line short" />
              </div>
            ))}
          </div>
        </div>
      ) : filter === "all" ? (
        allItems.length || tweets.length ? (
          <div className="news-overview">
            {spotlightNews.length > 0 && (
              <section className="news-spotlight" aria-labelledby="news-spotlight-title">
                <div className="news-block-heading">
                  <div>
                    <span className="news-block-kicker">GÜNDEM</span>
                    <h2 id="news-spotlight-title">Öne çıkan gelişmeler</h2>
                  </div>
                  <button type="button" onClick={() => selectFilter("news")}>
                    Tüm haberler <ArrowRight size={15} aria-hidden="true" />
                  </button>
                </div>
                <div
                  className={`news-spotlight-grid ${spotlightNews.length === 1 ? "news-spotlight-single" : ""}`}
                >
                  {spotlightNews[0] && (
                    <NewsCard
                      item={spotlightNews[0]}
                      featured
                      onAnalyze={onAnalyze}
                      event={eventByItem.get(spotlightNews[0].id)}
                    />
                  )}
                  <div className="news-spotlight-list">
                    {spotlightNews.slice(1).map((item) => (
                      <NewsCard
                        item={item}
                        key={item.id}
                        onAnalyze={onAnalyze}
                        event={eventByItem.get(item.id)}
                      />
                    ))}
                  </div>
                </div>
              </section>
            )}
            <section className="news-official-block" aria-labelledby="news-official-title">
              <div className="news-block-heading">
                <div>
                  <span className="news-block-kicker">RESMÎ KAYNAK</span>
                  <h2 id="news-official-title">Siber Güvenlik Başkanlığı bildirimleri</h2>
                </div>
                <button type="button" onClick={() => selectFilter("official")}>
                  Tüm bildirimler <ArrowRight size={15} aria-hidden="true" />
                </button>
              </div>
              {displayByCategory.official.length ? (
                <div className="news-official-grid">
                  {displayByCategory.official.slice(0, 3).map((item) => (
                    <NewsCard
                      item={item}
                      key={item.id}
                      onAnalyze={onAnalyze}
                      event={eventByItem.get(item.id)}
                    />
                  ))}
                </div>
              ) : (
                <p className="news-empty">Resmî bildirimlere şu an ulaşılamıyor.</p>
              )}
            </section>
            <section
              className="news-official-block news-privacy-block"
              aria-labelledby="news-privacy-title"
            >
              <div className="news-block-heading">
                <div>
                  <span className="news-block-kicker">KİŞİSEL VERİLERİ KORUMA KURUMU</span>
                  <h2 id="news-privacy-title">KVKK veri ihlali bildirimleri</h2>
                </div>
                <button type="button" onClick={() => selectFilter("privacy")}>
                  Tüm bildirimler <ArrowRight size={15} aria-hidden="true" />
                </button>
              </div>
              {displayByCategory.privacy.length ? (
                <div className="news-official-grid">
                  {displayByCategory.privacy.slice(0, 3).map((item) => (
                    <NewsCard
                      item={item}
                      key={item.id}
                      onAnalyze={onAnalyze}
                      event={eventByItem.get(item.id)}
                    />
                  ))}
                </div>
              ) : (
                <p className="news-empty">KVKK bildirimlerine şu an ulaşılamıyor.</p>
              )}
            </section>
            {(radarNew.length > 0 || radarKev.length > 0) && (
              <section className="news-radar" aria-label="CVE Radar">
                <div className="news-block-heading">
                  <div>
                    <span className="news-block-kicker">RESMÎ CVE VERİLERİ</span>
                    <h2>CVE Radar</h2>
                  </div>
                </div>
                <div className="news-radar-columns">
                  <div>
                    <h3>Yeni yayımlanan CVE'ler</h3>
                    {radarNew.length ? (
                      radarNew
                        .slice(0, 4)
                        .map((item) => <NewsCard item={item} key={item.id} onAnalyze={onAnalyze} />)
                    ) : (
                      <p className="news-empty">Doğrulanmış yeni yayın tarihi bulunan CVE yok.</p>
                    )}
                  </div>
                  <div>
                    <h3>Güncel istismar / CISA KEV</h3>
                    {radarKev.length ? (
                      radarKev
                        .slice(0, 4)
                        .map((item) => <NewsCard item={item} key={item.id} onAnalyze={onAnalyze} />)
                    ) : (
                      <p className="news-empty">
                        {data?.enrichment && !data.enrichment.kev_available
                          ? "KEV kataloğuna ulaşılamadı; eşleşme bilinmiyor."
                          : "KEV eşleşmesi bulunamadı."}
                      </p>
                    )}
                  </div>
                </div>
              </section>
            )}
            <div className="news-brief-grid">
              {(["cve", "ioc"] as const).map((category) => (
                <section className={`news-brief news-brief-${category}`} key={category}>
                  <div className="news-block-heading">
                    <div>
                      <span className="news-block-kicker">
                        {category === "cve" ? "ZAFİYETLER" : "GÖSTERGELER"}
                      </span>
                      <h2>{category === "cve" ? "CVE kayıtları" : "Son IOC kayıtları"}</h2>
                    </div>
                    <button type="button" onClick={() => selectFilter(category)}>
                      Tümünü gör <ArrowRight size={15} aria-hidden="true" />
                    </button>
                  </div>
                  {displayByCategory[category].length ? (
                    <div className="news-brief-list">
                      {displayByCategory[category].slice(0, 3).map((item) => (
                        <NewsCard
                          item={item}
                          key={item.id}
                          onAnalyze={onAnalyze}
                          event={eventByItem.get(item.id)}
                        />
                      ))}
                    </div>
                  ) : (
                    <p className="news-empty">Bu akışta kayıt yok.</p>
                  )}
                </section>
              ))}
            </div>
            <section className="news-tweets-block" aria-labelledby="news-tweets-title">
              <div className="news-block-heading">
                <div>
                  <span className="news-block-kicker">X / SOSYAL İSTİHBARAT</span>
                  <h2 id="news-tweets-title">X tehdit istihbaratı</h2>
                  {tweetAccounts.length > 0 && (
                    <p className="news-tweets-meta">
                      {tweetAccounts.map((account) => `@${account.username}`).join(" · ")} —{" "}
                      {tweetAccounts[0]?.fetched_at
                        ? `son çekim ${formatDate(tweetAccounts[0].fetched_at)}`
                        : "çekim bekleniyor"}
                    </p>
                  )}
                </div>
                <button type="button" onClick={() => selectFilter("x")}>
                  Tümünü gör <ArrowRight size={15} aria-hidden="true" />
                </button>
              </div>
              {tweets.length ? (
                <div className="tweet-grid">
                  {groupedTweets.slice(0, 6).map((tweet) => (
                    <TweetCard
                      tweet={tweet}
                      key={tweet.id}
                      relatedCount={tweetGroups.get(tweet.group_id ?? tweet.id)}
                      linkedEvent={data?.events?.find(
                        (event) => event.id === tweet.linked_event_id,
                      )}
                    />
                  ))}
                </div>
              ) : (
                <p className="news-empty">Henüz tweet verisi yok.</p>
              )}
            </section>
          </div>
        ) : (
          <p className="news-empty">Gösterilecek kayıt bulunamadı.</p>
        )
      ) : filter === "x" ? (
        <section className="news-category-view" aria-label="X tehdit istihbaratı listesi">
          <div className="news-block-heading">
            <div>
              <span className="news-block-kicker">
                X / SOSYAL İSTİHBARAT / {tweets.length} GÖNDERİ
              </span>
              <h2>X tehdit istihbaratı</h2>
              {tweetAccounts.length > 0 && (
                <p className="news-tweets-meta">
                  {tweetAccounts.map((account) => `@${account.username}`).join(" · ")}
                </p>
              )}
            </div>
          </div>
          {tweets.length ? (
            <>
              <div className="tweet-grid tweet-grid-list">
                {groupedTweets.slice(0, visibleCount).map((tweet) => (
                  <TweetCard
                    tweet={tweet}
                    key={tweet.id}
                    relatedCount={tweetGroups.get(tweet.group_id ?? tweet.id)}
                    linkedEvent={data?.events?.find((event) => event.id === tweet.linked_event_id)}
                  />
                ))}
              </div>
              {tweets.length > visibleCount && (
                <Button
                  className="news-more"
                  variant="secondary"
                  onClick={() => setVisibleCount((count) => count + 20)}
                >
                  Daha fazla göster
                </Button>
              )}
            </>
          ) : (
            <p className="news-empty">
              {tweetAccounts.length ? "Henüz tweet verisi yok." : "X akışı yapılandırılmamış."}
            </p>
          )}
        </section>
      ) : (
        <section
          className="news-category-view"
          aria-label={`${FILTERS.find((option) => option.id === filter)?.label} listesi`}
        >
          <div className="news-block-heading">
            <div>
              <span className="news-block-kicker">KATEGORİ / {items.length} KAYIT</span>
              <h2>
                {filter === "news"
                  ? "Haberler"
                  : filter === "official"
                    ? "Resmî bildirimler"
                    : filter === "privacy"
                      ? "KVKK veri ihlali bildirimleri"
                      : filter === "cve"
                        ? "CVE kayıtları"
                        : "IOC kayıtları"}
              </h2>
            </div>
          </div>
          {items.length ? (
            <>
              <div className="news-category-list">
                {items.slice(0, visibleCount).map((item) => (
                  <NewsCard
                    item={item}
                    key={item.id}
                    onAnalyze={onAnalyze}
                    event={eventByItem.get(item.id)}
                  />
                ))}
              </div>
              {items.length > visibleCount && (
                <Button
                  className="news-more"
                  variant="secondary"
                  onClick={() => setVisibleCount((count) => count + 20)}
                >
                  Daha fazla göster
                </Button>
              )}
            </>
          ) : (
            <p className="news-empty">
              {failedSources > 0 ? "Bu akış şu an okunamıyor." : "Bu kategoride kayıt bulunamadı."}
            </p>
          )}
        </section>
      )}

      {data && (
        <div className="news-resources">
          <details className="news-source-details">
            <summary>
              <span>Veri kaynakları</span>
              <span className={`news-resource-status ${failedSources ? "warn" : ""}`}>
                {`${okSources}/${totalSources} erişilebilir`}
              </span>
            </summary>
            <div className="news-source-list">
              {data.sources.map((source) => (
                <div className="news-source" key={source.id}>
                  <span className={`news-source-dot ${source.status === "ok" ? "ok" : "error"}`} />
                  <div>
                    <strong>{source.name}</strong>
                    <small>
                      {HEALTH_NAMES[
                        source.health_state ?? (source.status === "ok" ? "working" : "unreachable")
                      ] ?? "Durum bilinmiyor"}{" "}
                      · {source.count} kayıt
                    </small>
                    <small>
                      Son kontrol: {formatDate(source.checked_at ?? null)} · Son başarılı çekim:{" "}
                      {formatDate(source.last_success_at ?? null)}
                    </small>
                    <small>
                      Son içerik: {formatDate(source.latest_item_published_at ?? null)} · Önbellek:{" "}
                      {source.cache_age_seconds == null
                        ? "bilinmiyor"
                        : `${Math.round(source.cache_age_seconds / 60)} dk`}
                    </small>
                    {source.expected_frequency && (
                      <small>
                        Beklenen yayın sıklığı:{" "}
                        {source.expected_frequency === "daily" ? "günlük" : "düzensiz"}
                      </small>
                    )}
                    {source.status !== "ok" && (
                      <small>
                        HTTP {source.http_status ?? "—"} · Hata: {source.error_kind ?? "bilinmiyor"}
                      </small>
                    )}
                  </div>
                </div>
              ))}
              <p>RSS ve resmî bildirimler sunucuda okunur, 10 dakika önbellekte tutulur.</p>
            </div>
          </details>
          <div className="news-official-links">
            <span>RESMÎ DUYURULAR</span>
            {data.official_links.map((source) => (
              <a key={source.url} href={source.url} target="_blank" rel="noopener noreferrer">
                {source.name}
                <ExternalLink size={13} aria-hidden="true" />
              </a>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
