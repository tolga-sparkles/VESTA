import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { Vesta } from "@/routes/index";
import type { SearchEvent } from "@/lib/vesta-data";

const searchMock = vi.hoisted(() => vi.fn());

vi.mock("@/lib/vesta-data", async (importOriginal) => {
  const original = await importOriginal<typeof import("@/lib/vesta-data")>();
  return {
    ...original,
    fetchSession: vi.fn().mockResolvedValue({ authenticated: true }),
    fetchNews: vi.fn().mockResolvedValue({
      items: [],
      sources: [],
      official_links: [],
      fetched_at: "",
      tweets: { accounts: [], tweets: [], fetched_at: "" },
    }),
    fetchUsage: vi.fn().mockResolvedValue({
      searches_24h: 0,
      requests_24h: {},
      abuseipdb_today_utc: 0,
      virustotal_minute: 0,
      virustotal_24h: 0,
    }),
    searchStream: searchMock,
  };
});

describe("Alan adı ve IP analizi", () => {
  it("kaynakları ve puanları ayırır, teknik profili çözümlenen IP'den gösterir", async () => {
    const events: SearchEvent[] = [
      {
        event: "start",
        indicator: "example.com",
        kind: "domain",
        sources: ["abuseipdb", "internetdb"],
      },
      { event: "dns", status: "ok", addresses: ["8.8.8.8"], selected: "8.8.8.8" },
      {
        event: "result",
        indicator: "example.com",
        kind: "domain",
        source: "abuseipdb",
        status: "no_match",
        summary: "Alan adı bulgusu",
        details: null,
        elapsed_ms: 1,
      },
      {
        event: "score",
        indicator: "example.com",
        kind: "domain",
        value: 10,
        evaluated: 1,
        applicable: 1,
        provisional: false,
        breakdown: [],
      },
      {
        event: "result",
        indicator: "8.8.8.8",
        kind: "ipv4",
        source: "abuseipdb",
        status: "match",
        summary: "IP bulgusu",
        details: { isp: "Örnek ISP" },
        elapsed_ms: 1,
      },
      {
        event: "result",
        indicator: "8.8.8.8",
        kind: "ipv4",
        source: "internetdb",
        status: "match",
        summary: "Port bulgusu",
        details: { ports: [443], vulns: [], hostnames: [], cpes: [] },
        elapsed_ms: 1,
      },
      {
        event: "score",
        indicator: "8.8.8.8",
        kind: "ipv4",
        value: 40,
        evaluated: 2,
        applicable: 2,
        provisional: false,
        breakdown: [],
      },
      { event: "done" },
    ];
    searchMock.mockImplementation(
      async (_indicator, _signal, onEvent: (event: SearchEvent) => void) => {
        events.forEach(onEvent);
      },
    );

    render(<Vesta />);
    fireEvent.change(await screen.findByRole("textbox", { name: "IP adresi veya alan adı" }), {
      target: { value: "example.com" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Analiz Et" }));

    expect(await screen.findByText("Alan adı bulgusu")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Çözümlenen IP adresi" })).toBeInTheDocument();
    expect(screen.getByText("Örnek ISP")).toBeInTheDocument();
    expect(screen.getByText("443", { selector: ".port-num a" })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "Alan adı risk puanı: 10 / 100" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Çözümlenen IP · 8\.8\.8\.8/ }));
    expect(screen.getByText("IP bulgusu")).toBeInTheDocument();
    expect(screen.queryByText("Alan adı bulgusu")).not.toBeInTheDocument();
    expect(screen.getByRole("img", { name: "IP risk puanı: 40 / 100" })).toBeInTheDocument();
  });

  it("özel DNS adresini gösterir fakat IP analizi açmaz", async () => {
    const events: SearchEvent[] = [
      { event: "start", indicator: "gaziantep.bel.tr", kind: "domain", sources: ["abuseipdb"] },
      { event: "dns", status: "no_public_ip", addresses: ["10.1.227.151"], selected: null },
      { event: "done" },
    ];
    searchMock.mockImplementation(
      async (_indicator, _signal, onEvent: (event: SearchEvent) => void) => {
        events.forEach(onEvent);
      },
    );

    render(<Vesta />);
    fireEvent.change(await screen.findByRole("textbox", { name: "IP adresi veya alan adı" }), {
      target: { value: "gaziantep.bel.tr" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Analiz Et" }));

    expect(await screen.findByText("10.1.227.151")).toBeInTheDocument();
    expect(
      screen.getByText("Bu adres özel veya yerel ağda; dış kaynaklarla IP analizi yapılmaz."),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Çözümlenen IP/ })).not.toBeInTheDocument();
  });
});
