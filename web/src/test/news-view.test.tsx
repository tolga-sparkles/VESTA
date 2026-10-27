import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { NewsView } from "@/components/news-view";
import type { NewsSnapshot } from "@/lib/vesta-data";

function snapshot(items: NewsSnapshot["items"], tweets: NewsSnapshot["tweets"]): NewsSnapshot {
  return {
    items,
    sources: [],
    official_links: [],
    fetched_at: "2026-10-13T12:00:00+00:00",
    tweets,
  };
}

const tweets = {
  accounts: [
    {
      username: "CyberPulse56",
      status: "completed",
      fetched_at: "2026-10-13T12:00:00+03:00",
      count: 1,
    },
  ],
  tweets: [
    {
      id: "1",
      created_at: "2026-10-13T12:14:40+00:00",
      text: "DDoS CLAIM",
      lang: "en",
      favorite_count: 0,
      retweet_count: 0,
      reply_count: 0,
      quote_count: 0,
      view_count: 64,
      username: "CyberPulse56",
      name: "CyberPulse",
      media: [],
    },
  ],
  fetched_at: "2026-10-13T12:00:00+00:00",
};

describe("NewsView overview", () => {
  it("shows the X block in overview even when RSS items are empty", () => {
    render(<NewsView data={snapshot([], tweets)} loading={false} error="" onRefresh={() => {}} />);
    expect(screen.getByText("X tehdit istihbaratı")).toBeInTheDocument();
    expect(screen.getByText("DDoS CLAIM")).toBeInTheDocument();
  });

  it("shows the empty message when there are neither items nor tweets", () => {
    const empty = { accounts: [], tweets: [], fetched_at: "2026-10-13T12:00:00+00:00" };
    render(<NewsView data={snapshot([], empty)} loading={false} error="" onRefresh={() => {}} />);
    expect(screen.getByText("Gösterilecek kayıt bulunamadı.")).toBeInTheDocument();
  });

  it("keeps a social claim unverified and allows compact expansion", () => {
    const longTweet = {
      ...tweets,
      tweets: [{ ...tweets.tweets[0], text: "DDoS CLAIM ".repeat(25) }],
    };
    render(
      <NewsView data={snapshot([], longTweet)} loading={false} error="" onRefresh={() => {}} />,
    );
    expect(screen.getByText("Doğrulanmamış sosyal medya bildirimi")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Tamamını göster" }));
    expect(screen.getByRole("button", { name: "Daralt" })).toBeInTheDocument();
  });

  it("passes a news IOC to Analyze without starting a search", () => {
    const calls: string[] = [];
    const item: NewsSnapshot["items"][number] = {
      id: "ioc-1",
      source_id: "siberkapan-ioc",
      source: "SiberKapan IOC",
      category: "ioc",
      title: "8.8.8.8 tehdit göstergesi",
      summary: "Test kaydı",
      url: "https://example.org/ioc-1",
      published_at: "2026-10-13T12:00:00+00:00",
      evaluation: {
        content_type: "ioc",
        priority: "medium",
        verification: "single_source",
        rank_score: 38,
        rank_components: {
          evidence: 0,
          relevance: 20,
          urgency: 0,
          freshness: 18,
          independent_support: 0,
        },
        reasons: [],
        indicators: { cves: [], ips: ["8.8.8.8"], domains: [] },
        active_exploitation: false,
        region: "global",
        source_count: 1,
        independent_source_count: 1,
      },
    };
    render(
      <NewsView
        data={snapshot([item], { accounts: [], tweets: [], fetched_at: "" })}
        loading={false}
        error=""
        onRefresh={() => {}}
        onAnalyze={(value) => calls.push(value)}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "VESTA'da Analiz Et: 8.8.8.8" }));
    expect(calls).toEqual(["8.8.8.8"]);
  });
});
