import { countryCentroid } from "./country-centroids";
import type { IndicatorKind, ScoreSnapshot, SourceId } from "./vesta-data";

export const CONTRIBUTION_ORDER: SourceId[] = [
  "abuseipdb",
  "virustotal",
  "internetdb",
  "otx",
  "sgb",
  "threatfox",
  "urlhaus",
  "mxtoolbox",
];

export function contributionRows(score: ScoreSnapshot | null, finished: boolean) {
  const rows = CONTRIBUTION_ORDER.map((source) => {
    const entry = score?.breakdown.find((part) => part.source === source);
    return { source, points: entry?.points ?? 0, max: entry?.max ?? 0 };
  });
  return finished ? rows.filter((row) => row.points > 0) : rows;
}

export type CountryRow = { code: string; name: string | null; sources: SourceId[] };

export function displayCountry(row: CountryRow) {
  if (row.name && row.name.toUpperCase() !== row.code) return row.name;
  try {
    return new Intl.DisplayNames(["tr"], { type: "region" }).of(row.code) ?? row.code;
  } catch {
    return row.code;
  }
}

export function resolveIpLocation(
  kind: IndicatorKind | null,
  rows: CountryRow[],
  otx: Record<string, unknown> | null | undefined,
) {
  const empty = {
    primary: null as CountryRow | null,
    alternatives: [] as CountryRow[],
    coordinates: null as [number, number] | null,
    coordinateSource: null as "otx" | "country" | null,
    city: null as string | null,
  };
  if (kind !== "ipv4" && kind !== "ipv6") return empty;

  const primary =
    (["abuseipdb", "virustotal", "otx"] as SourceId[])
      .map((source) => rows.find((row) => row.sources.includes(source)))
      .find(Boolean) ?? null;
  if (!primary) return empty;

  const otxAgrees = primary.sources.includes("otx");
  const lat = otx?.["latitude"];
  const lng = otx?.["longitude"];
  const validOtxCoordinates =
    otxAgrees &&
    typeof lat === "number" &&
    typeof lng === "number" &&
    Number.isFinite(lat) &&
    Number.isFinite(lng) &&
    Math.abs(lat) <= 90 &&
    Math.abs(lng) <= 180 &&
    !(lat === 0 && lng === 0);
  const coordinates: [number, number] | null = validOtxCoordinates
    ? [lat as number, lng as number]
    : countryCentroid(primary.code);
  const city =
    otxAgrees && typeof otx?.["city"] === "string" && otx["city"].trim()
      ? otx["city"].trim()
      : null;

  return {
    primary,
    alternatives: rows.filter((row) => row.code !== primary.code),
    coordinates,
    coordinateSource: coordinates ? (validOtxCoordinates ? "otx" : "country") : null,
    city,
  };
}
