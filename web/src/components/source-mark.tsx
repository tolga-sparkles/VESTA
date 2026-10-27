import type { SourceId } from "@/lib/vesta-data";

export function SourceMark({ id }: { id: SourceId }) {
  return (
    <span className={`source-mark mark-${id}`} aria-hidden="true">
      {id === "abuseipdb" && (
        <svg viewBox="0 0 32 32">
          <circle cx="16" cy="16" r="11" />
          <path d="M8 24 24 8" />
        </svg>
      )}
      {id === "otx" && (
        <svg viewBox="0 0 32 32">
          <path d="M16 3C1 3 3 23 16 29 29 23 31 3 16 3Z" />
          <path className="alien-eye" d="m7 13 7 5-4 2Zm18 0-7 5 4 2Z" />
        </svg>
      )}
      {id === "virustotal" && (
        <svg viewBox="0 0 32 32">
          <path d="M4 4h24v24H4l11-12Z" />
        </svg>
      )}
      {id === "threatfox" && (
        <svg viewBox="0 0 32 32">
          <path d="m5 3 7 7h8l7-7-2 17-9 9-9-9Z" />
          <path className="fox-face" d="m9 16 5 4-3 2Zm14 0-5 4 3 2ZM13 25l3-4 3 4Z" />
        </svg>
      )}
      {id === "urlhaus" && <span>U</span>}
      {id === "sgb" && (
        <img
          src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSeMO86iBQw801cIEv7lUzxs0pGGkoE3NJtNSsrn81fVg&s=10"
          alt=""
          className="sgb-logo"
        />
      )}
      {id === "internetdb" && (
        <svg viewBox="0 0 32 32">
          <circle cx="10" cy="13" r="6" />
          <circle cx="21" cy="8" r="5" />
          <circle cx="22" cy="23" r="6" />
        </svg>
      )}
      {id === "mxtoolbox" && (
        <img
          src="https://157.230.84.49/wp-content/uploads/2026/04/mxtoolbox.jpg"
          alt=""
          className="mxtoolbox-logo"
        />
      )}
    </span>
  );
}
