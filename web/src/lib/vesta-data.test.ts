import { describe, expect, it } from "vitest";
import { cpeLabel, detectIndicatorType, flagEmoji } from "./vesta-data";

describe("indicator validation", () => {
  it("detects valid IPv4 and rejects invalid octets", () => {
    expect(detectIndicatorType("203.0.113.42")).toBe("ipv4");
    expect(detectIndicatorType("999.0.113.42")).toBe(null);
    expect(detectIndicatorType("203.0.113")).toBe(null);
    expect(detectIndicatorType("8.8.8.8")).toBe("ipv4");
  });
  it("detects domains without accepting URLs", () => {
    expect(detectIndicatorType("example.com")).toBe("domain");
    expect(detectIndicatorType("https://example.com")).toBe(null);
    expect(detectIndicatorType("a..com")).toBe(null);
  });
  it("parses CPE 2.3 into readable labels without guessing", () => {
    expect(cpeLabel("cpe:2.3:a:google:chrome:120.0.0:*:*:*:*:*:*:*")).toBe(
      "google chrome (120.0.0)",
    );
    expect(cpeLabel("cpe:2.3:a:apache:http_server:2.4.57")).toBe("apache http_server (2.4.57)");
    expect(cpeLabel("cpe:2.3:a:*:unknown:*")).toBe("unknown");
    expect(cpeLabel("cpe:2.3:a:*:*:*")).toBe(null);
    expect(cpeLabel("rubbish")).toBe(null);
  });
  it("builds flags from ISO country codes only", () => {
    expect(flagEmoji("de")).toBe("🇩🇪");
    expect(flagEmoji("TR")).toBe("🇹🇷");
    expect(flagEmoji("usa")).toBe(null);
    expect(flagEmoji("")).toBe(null);
  });
});
