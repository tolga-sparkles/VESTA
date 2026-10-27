import type { NewsItem } from "@/lib/vesta-data";

function tickerHeadlines(items: NewsItem[]): NewsItem[] {
  const sourceCounts = new Map<string, number>();
  return items
    .filter((item) => {
      if (item.category === "ioc") return false;
      const count = sourceCounts.get(item.source_id) ?? 0;
      if (count >= 2) return false;
      sourceCounts.set(item.source_id, count + 1);
      return true;
    })
    .slice(0, 10);
}

export function SocTicker({
  items,
  loading,
  error,
}: {
  items: NewsItem[];
  loading: boolean;
  error: string;
}) {
  const headlines = tickerHeadlines(items);

  return (
    <section className="soc-ticker" aria-label="SOC haber akışı">
      <span className="soc-ticker-label">SOC AKIŞI</span>
      {headlines.length ? (
        <div className="soc-ticker-window">
          <div className="soc-ticker-track">
            {[false, true].map((duplicate) => (
              <div
                className="soc-ticker-group"
                key={String(duplicate)}
                aria-hidden={duplicate ? "true" : undefined}
              >
                {headlines.map((item) => (
                  <a
                    className="soc-ticker-item"
                    href={item.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    tabIndex={duplicate ? -1 : undefined}
                    key={item.id}
                    title={`${item.source}: ${item.title}`}
                  >
                    <span className="soc-ticker-source">{item.source}</span>
                    <span>{item.title}</span>
                  </a>
                ))}
              </div>
            ))}
          </div>
        </div>
      ) : (
        <span className="soc-ticker-placeholder">
          {loading
            ? "RSS başlıkları yükleniyor…"
            : error
              ? "RSS akışı şu an okunamıyor."
              : "Güncel haber bulunamadı."}
        </span>
      )}
    </section>
  );
}
