import { describe, expect, it } from "vitest";
import { contributionRows, resolveIpLocation, type CountryRow } from "./analysis-view";
import type { ScoreSnapshot } from "./vesta-data";

const score: ScoreSnapshot = {
  value: 27,
  evaluated: 3,
  applicable: 8,
  provisional: true,
  breakdown: [
    { source: "abuseipdb", points: 20, max: 35 },
    { source: "virustotal", points: 0, max: 25 },
    { source: "otx", points: 7, max: 10 },
  ],
};

describe("source contributions", () => {
  it("keeps all eight sources before and during analysis", () => {
    expect(contributionRows(null, false)).toHaveLength(8);
    const pending = contributionRows(score, false);
    expect(pending).toHaveLength(8);
    expect(pending.map((row) => row.source)).toEqual([
      "abuseipdb",
      "virustotal",
      "internetdb",
      "otx",
      "sgb",
      "threatfox",
      "urlhaus",
      "mxtoolbox",
    ]);
    expect(pending.find((row) => row.source === "abuseipdb")?.points).toBe(20);
    expect(pending.find((row) => row.source === "internetdb")?.points).toBe(0);
  });

  it("shows only positive contributors after the done event", () => {
    expect(contributionRows(score, true).map((row) => row.source)).toEqual(["abuseipdb", "otx"]);
    expect(contributionRows(null, true)).toEqual([]);
  });
});

describe("IP location", () => {
  const disagreeing: CountryRow[] = [
    { code: "TR", name: "Türkiye", sources: ["otx"] },
    { code: "US", name: null, sources: ["abuseipdb"] },
    { code: "DE", name: null, sources: ["virustotal"] },
  ];

  it("prioritizes AbuseIPDB and preserves conflicting countries", () => {
    const location = resolveIpLocation("ipv4", disagreeing, {
      latitude: 39,
      longitude: 35,
      city: "Ankara",
    });
    expect(location.primary?.code).toBe("US");
    expect(location.alternatives.map((row) => row.code)).toEqual(["TR", "DE"]);
    expect(location.coordinateSource).toBe("country");
    expect(location.city).toBeNull();
  });

  it("uses valid OTX coordinates only when its country agrees", () => {
    const rows: CountryRow[] = [{ code: "TR", name: "Türkiye", sources: ["abuseipdb", "otx"] }];
    const location = resolveIpLocation("ipv4", rows, {
      latitude: 39.93,
      longitude: 32.86,
      city: "Ankara",
    });
    expect(location.coordinates).toEqual([39.93, 32.86]);
    expect(location.coordinateSource).toBe("otx");
    expect(location.city).toBe("Ankara");
    expect(resolveIpLocation("ipv4", rows, { latitude: 0, longitude: 0 }).coordinateSource).toBe(
      "country",
    );
  });

  it("does not map a domain or invent coordinates without a known country", () => {
    expect(resolveIpLocation("domain", disagreeing, null).coordinates).toBeNull();
    expect(resolveIpLocation("ipv4", [], null).coordinates).toBeNull();
  });
});
