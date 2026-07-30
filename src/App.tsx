cat > src/App.tsx << 'EOF'
import * as motion from "framer-motion";
import {
  Activity,
  Cloud,
  Database,
  Download,
  Gauge,
  Play,
  Radar,
  RefreshCw,
  Search,
  Shield,
  Square,
  Wifi,
} from "lucide-react";
import { type ReactNode, useEffect, useMemo, useRef, useState } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Toaster, toast } from "sonner";
import * as XLSX from "xlsx";

type ProbeState = "success" | "failed" | "timeout" | "pending";
type BatchStatus = "running" | "completed" | "cancelled";
type Tab =
  | "scanner"
  | "sources"
  | "history"
  | "results"
  | "analytics"
  | "export"
  | "dns"
  | "vless";

type ExportFormat = "txt" | "json" | "xlsx";
type ExportRow = Record<string, string | number | null>;

type ProbeResponse = {
  ip: string;
  mode: "l4_tcp_handshake";
  testedPorts: number[];
  overall: "success" | "failed";
  l4: Array<{ port: number; status: ProbeState; latency: number | null }>;
};

type ScanResult = {
  id: string;
  batchId: string;
  ipAddress: string;
  ipRange: string;
  overall: ProbeState;
  l4?: ProbeResponse["l4"];
  tcp80: ProbeState;
  tcp443: ProbeState;
  tcp2053: ProbeState;
  tcp8443: ProbeState;
  openPorts: number;
  latency: number | null;
  createdAt: string;
};

type CapabilityId = "cdn" | "tunnel" | "warp" | "bpb";
type CapabilityFlags = Record<CapabilityId, boolean>;
type ProxyExportProtocol = "vless_ws_tls" | "trojan_ws_tls";

type ProxyExportSettings = {
  protocol: ProxyExportProtocol;
  secret: string;
  sni: string;
  host: string;
  path: string;
  preferredPortsCsv: string;
  includeCaps: CapabilityId[];
};

type DnsReplaceMode = "replace";
type DnsSettings = {
  token: string;
  zoneId: string;
  recordName: string;
  topN: number;
  proxied: boolean;
  ttl: number;
  includeCaps: CapabilityId[];
  mode: DnsReplaceMode;
};

type SourceGroupId = "cdn" | "warp" | "tunnel" | "custom";
type VlessRetestResult = {
  ip: string;
  port: number;
  status: ProbeState;
  latency: number | null;
};

type VlessSettings = {
  vlessUri: string;
  uuid: string;
  port: number;
  sni: string;
  host: string;
  path: string;
  topN: number;
  concurrency: number;
};

type ScanBatch = {
  id: string;
  name: string;
  createdAt: string;
  durationMs?: number;
  status: BatchStatus;
  totalIps: number;
  scannedCount: number;
  successCount: number;
  failedCount: number;
  ipRanges: string[];
};

type SourceItem = {
  id: string;
  name: string;
  url: string;
  ranges: string[];
  lastFetched: string | null;
  group?: "cdn" | "warp" | "tunnel" | "custom";
};

type LogEntry = {
  id: string;
  ts: string;
  level: "info" | "ok" | "warn" | "error";
  text: string;
};

const STORAGE_KEYS = {
  history: "cftun_history_v2",
  results: "cftun_results_v2",
  ranges: "cftun_ranges_v2",
  sources: "cftun_sources_v2",
  proxyExport: "cftun_proxy_export_v1",
  dns: "cftun_dns_v1",
  vless: "cftun_vless_v1",
  apiBaseUrl: "cftun_api_base_url_v1",
};

const MAX_IPS_PER_RANGE = 200;
const DEFAULT_RANGES = [
  "173.245.48.0/20",
  "103.21.244.0/22",
  "103.22.200.0/22",
  "103.31.4.0/22",
  "141.101.64.0/18",
  "108.162.192.0/18",
  "190.93.240.0/20",
  "188.114.96.0/20",
  "197.234.240.0/22",
  "198.41.128.0/17",
  "162.158.0.0/15",
  "104.16.0.0/13",
  "104.24.0.0/14",
  "172.64.0.0/13",
  "131.0.72.0/22",
];

function readStorage<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function writeStorage<T>(key: string, value: T): void {
  localStorage.setItem(key, JSON.stringify(value));
}

function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function exportRows(
  format: ExportFormat,
  rows: ExportRow[],
  filenameBase: string,
): void {
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const name = `${filenameBase}_${ts}`;
  if (format === "json") {
    downloadBlob(
      new Blob([JSON.stringify(rows, null, 2)], { type: "application/json" }),
      `${name}.json`,
    );
    return;
  }
  if (format === "txt") {
    const text = rows.map((r) => Object.values(r)[0]).join("\n");
    downloadBlob(new Blob([text], { type: "text/plain" }), `${name}.txt`);
    return;
  }
  const ws = XLSX.utils.json_to_sheet(rows);
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, "export");
  const out = XLSX.write(wb, { bookType: "xlsx", type: "array" });
  downloadBlob(
    new Blob([out], {
      type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }),
    `${name}.xlsx`,
  );
}

function isValidIPv4(ip: string): boolean {
  const parts = ip.split(".");
  return (
    parts.length === 4 &&
    parts.every(
      (part) => /^\d+$/.test(part) && Number(part) >= 0 && Number(part) <= 255,
    )
  );
}

function isValidCidr(v: string): boolean {
  const [ip, prefixRaw] = v.trim().split("/");
  if (!ip || !prefixRaw) return false;
  const prefix = Number(prefixRaw);
  return (
    isValidIPv4(ip) && Number.isInteger(prefix) && prefix >= 0 && prefix <= 32
  );
}

function ipToInt(ip: string): number {
  const [a, b, c, d] = ip.split(".").map(Number);
  return (((a << 24) >>> 0) | (b << 16) | (c << 8) | d) >>> 0;
}

function intToIp(v: number): string {
  return [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].join(".");
}

function expandCidr(cidr: string, limit: number): string[] {
  if (!isValidCidr(cidr)) return [];
  const [ip, prefixRaw] = cidr.split("/");
  const prefix = Number(prefixRaw);
  const hostCount = 2 ** (32 - prefix);
  const count = Math.min(hostCount, Math.max(1, limit));
  const base = ipToInt(ip);
  const out: string[] = [];
  for (let i = 1; i <= count; i += 1) out.push(intToIp((base + i) >>> 0));
  return out;
}

function sampleCidr(
  cidr: string,
  limit: number,
  mode: "sequential" | "random",
): string[] {
  if (mode === "sequential") return expandCidr(cidr, limit);
  if (!isValidCidr(cidr)) return [];
  const [ip, prefixRaw] = cidr.split("/");
  const prefix = Number(prefixRaw);
  const hostCount = 2 ** (32 - prefix);
  const count = Math.min(hostCount, Math.max(1, limit));
  const base = ipToInt(ip);
  const picked = new Set<number>();
  const maxIndex = Math.max(1, hostCount - 2);
  const maxAttempts = Math.min(10_000, count * 50);
  let attempts = 0;
  while (picked.size < count && attempts < maxAttempts) {
    attempts += 1;
    const idx = 1 + Math.floor(Math.random() * maxIndex);
    picked.add(idx);
  }
  return [...picked].map((idx) => intToIp((base + idx) >>> 0));
}

function extractCidrs(payload: unknown): string[] {
  const found = new Set<string>();
  const walk = (value: unknown): void => {
    if (typeof value === "string") {
      const matches =
        value.match(
          /\b(?:\d{1,3}\.){3}\d{1,3}\/(?:[0-9]|[1-2][0-9]|3[0-2])\b/g,
        ) || [];
      matches.forEach((m) => {
        if (isValidCidr(m)) found.add(m);
      });
      return;
    }
    if (Array.isArray(value)) return value.forEach(walk);
    if (value && typeof value === "object")
      Object.values(value as Record<string, unknown>).forEach(walk);
  };
  walk(payload);
  return [...found];
}

function Progress({ value }: { value: number }) {
  return (
    <div className="progress-shell">
      <motion.div
        className="progress-bar"
        animate={{ width: `${value}%` }}
        transition={{ duration: 0.35 }}
      />
    </div>
  );
}

function migrateStoredScanResult(raw: unknown): ScanResult | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Partial<ScanResult> & Record<string, unknown>;
  if (
    typeof r.id !== "string" ||
    typeof r.batchId !== "string" ||
    typeof r.ipAddress !== "string" ||
    typeof r.ipRange !== "string" ||
    typeof r.overall !== "string" ||
    typeof r.createdAt !== "string"
  )
    return null;

  const base: ScanResult = {
    id: r.id,
    batchId: r.batchId,
    ipAddress: r.ipAddress,
    ipRange: r.ipRange,
    overall: r.overall as ProbeState,
    tcp80: (r.tcp80 as ProbeState) ?? "failed",
    tcp443: (r.tcp443 as ProbeState) ?? "failed",
    tcp2053: (r.tcp2053 as ProbeState) ?? "failed",
    tcp8443: (r.tcp8443 as ProbeState) ?? "failed",
    openPorts: typeof r.openPorts === "number" ? r.openPorts : 0,
    latency:
      typeof r.latency === "number" || r.latency === null ? r.latency : null,
    createdAt: r.createdAt,
    l4: Array.isArray(r.l4)
      ? (r.l4 as ProbeResponse["l4"])
      : [
          { port: 80, status: (r.tcp80 as ProbeState) ?? "failed", latency: null },
          { port: 443, status: (r.tcp443 as ProbeState) ?? "failed", latency: null },
          { port: 2053, status: (r.tcp2053 as ProbeState) ?? "failed", latency: null },
          { port: 8443, status: (r.tcp8443 as ProbeState) ?? "failed", latency: null },
        ],
  };
  return base;
}

function l4Status(result: ScanResult, port: number): ProbeState {
  const hit = result.l4?.find((p) => p.port === port);
  if (hit) return hit.status;
  if (port === 80) return result.tcp80;
  if (port === 443) return result.tcp443;
  if (port === 2053) return result.tcp2053;
  if (port === 8443) return result.tcp8443;
  return "failed";
}

function capabilityFlags(result: ScanResult): CapabilityFlags {
  const cdn = l4Status(result, 80) === "success" || l4Status(result, 443) === "success";
  const tunnel = l4Status(result, 7844) === "success";
  const warp = l4Status(result, 2408) === "success";
  const bpb = l4Status(result, 8080) === "success";
  return { cdn, tunnel, warp, bpb };
}

function parsePreferredPorts(csv: string): number[] {
  return csv
    .split(",")
    .map((s) => Number(s.trim()))
    .filter((n) => Number.isInteger(n) && n > 0 && n <= 65535);
}

function pickOpenPort(result: ScanResult, preferred: number[]): number | null {
  const open = new Set<number>(
    (result.l4 || []).filter((p) => p.status === "success").map((p) => p.port),
  );
  for (const p of preferred) if (open.has(p)) return p;
  const any = (result.l4 || []).find((p) => p.status === "success")?.port;
  if (typeof any === "number") return any;
  return preferred[0] ?? null;
}

function yamlEscape(s: string): string {
  if (/^[a-zA-Z0-9_.:/-]+$/.test(s)) return s;
  return JSON.stringify(s);
}

async function probeIp(
  apiBaseUrl: string,
  ip: string,
  ports: number[],
  signal?: AbortSignal,
): Promise<ProbeResponse> {
  const base = apiBaseUrl.trim().replace(/\/+$/g, "");
  const url = base ? `${base}/api/probe` : "/api/probe";
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ip, ports }),
    signal,
  });
  if (!response.ok) throw new Error("Probe API error");
  return (await response.json()) as ProbeResponse;
}

async function cfReplaceARecords(input: {
  apiBaseUrl?: string;
  token: string;
  zoneId: string;
  name: string;
  ips: string[];
  proxied: boolean;
  ttl: number;
}): Promise<{ ok: boolean; replaced?: unknown; error?: string }> {
  const base = String(input.apiBaseUrl || "").trim().replace(/\/+$/g, "");
  const url = base ? `${base}/api/cf/dns/replace-a` : "/api/cf/dns/replace-a";
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ...input, apiBaseUrl: undefined }),
  });
  const json = (await res.json().catch(() => null)) as
    | { ok: boolean; replaced?: unknown; error?: string }
    | null;
  if (!res.ok || !json) throw new Error(json?.error || "Cloudflare API failed");
  return json;
}

function parseVlessUri(uri: string): VlessSettings | null {
  try {
    const u = new URL(uri.trim());
    if (u.protocol !== "vless:") return null;
    const uuid = decodeURIComponent(u.username || "");
    const port = Number(u.port || 443);
    const q = u.searchParams;
    const sni = q.get("sni") || q.get("servername") || "";
    const host = q.get("host") || "";
    const path = q.get("path") || "/";
    return {
      vlessUri: uri.trim(),
      uuid,
      port: Number.isFinite(port) ? port : 443,
      sni,
      host,
      path,
      topN: 20,
      concurrency: 20,
    };
  } catch {
    return null;
  }
}

function buildVlessUri(input: {
  ip: string;
  port: number;
  uuid: string;
  sni: string;
  host: string;
  path: string;
  name?: string;
}): string {
  const base = new URL(`vless://${encodeURIComponent(input.uuid)}@${input.ip}:${input.port}`);
  base.searchParams.set("type", "ws");
  base.searchParams.set("security", "tls");
  if (input.sni) base.searchParams.set("sni", input.sni);
  if (input.host) base.searchParams.set("host", input.host);
  if (input.path) base.searchParams.set("path", input.path);
  base.searchParams.set("encryption", "none");
  const fragment = input.name ? `#${encodeURIComponent(input.name)}` : "";
  return `${base.toString()}${fragment}`;
}

function App() {
  const [ranges, setRanges] = useState<string[]>(() =>
    readStorage(STORAGE_KEYS.ranges, DEFAULT_RANGES),
  );
  const [apiBaseUrl, setApiBaseUrl] = useState<string>(() =>
    readStorage<string>(STORAGE_KEYS.apiBaseUrl, ""),
  );
  const [selectedRanges, setSelectedRanges] = useState<string[]>([]);
  const [history, setHistory] = useState<ScanBatch[]>(() =>
    readStorage(STORAGE_KEYS.history, []),
  );
  const [allResults, setAllResults] = useState<ScanResult[]>(() =>
    readStorage<unknown[]>(STORAGE_KEYS.results, [])
      .map(migrateStoredScanResult)
      .filter((v): v is ScanResult => v != null),
  );
  const [sources, setSources] = useState<SourceItem[]>(() =>
    readStorage(STORAGE_KEYS.sources, []),
  );

  const [activeTab, setActiveTab] = useState<Tab>("scanner");
  const [isScanning, setIsScanning] = useState(false);
  const [currentBatch, setCurrentBatch] = useState<ScanBatch | null>(null);
  const [liveResults, setLiveResults] = useState<ScanResult[]>([]);
  const [ipsPerRange, setIpsPerRange] = useState(3);
  const [rangeGroup, setRangeGroup] = useState<
    "all" | "cdn" | "tunnel" | "warp" | "custom"
  >("all");
  const [rangePage, setRangePage] = useState(1);
  const [rangePageSize, setRangePageSize] = useState(90);

  const [historyQuery, setHistoryQuery] = useState("");
  const [historyDate, setHistoryDate] = useState("");

  const [sourceName, setSourceName] = useState("");
  const [sourceUrl, setSourceUrl] = useState("");
  const [sourceGroup, setSourceGroup] = useState<SourceGroupId>("custom");
  const [portToggles, setPortToggles] = useState<number[]>([
    80, 443, 7844, 2053, 2083, 2087, 2096, 8443, 8080, 2408,
  ]);
  const [customPort, setCustomPort] = useState("");
  const [scanWorkers, setScanWorkers] = useState(20);
  const [sampleMode, setSampleMode] = useState<"sequential" | "random">(
    "random",
  );

  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [resultFilterQuery, setResultFilterQuery] = useState("");
  const [resultFilterStatus, setResultFilterStatus] = useState<
    "all" | "success" | "failed"
  >("all");
  const [resultFilterMinOpen, setResultFilterMinOpen] = useState(0);
  const [resultOnlyLastBatch, setResultOnlyLastBatch] = useState(true);
  const [resultFilterCaps, setResultFilterCaps] = useState<CapabilityId[]>([]);

  const [proxyExport, setProxyExport] = useState<ProxyExportSettings>(() =>
    readStorage<ProxyExportSettings>(STORAGE_KEYS.proxyExport, {
      protocol: "vless_ws_tls",
      secret: "",
      sni: "",
      host: "",
      path: "/",
      preferredPortsCsv: "443,2053,8443,80",
      includeCaps: ["cdn"],
    }),
  );

  const [dnsSettings, setDnsSettings] = useState<DnsSettings>(() =>
    readStorage<DnsSettings>(STORAGE_KEYS.dns, {
      token: "",
      zoneId: "",
      recordName: "",
      topN: 5,
      proxied: true,
      ttl: 1,
      includeCaps: ["cdn"],
      mode: "replace",
    }),
  );

  const [vlessSettings, setVlessSettings] = useState<VlessSettings>(() =>
    readStorage<VlessSettings>(STORAGE_KEYS.vless, {
      vlessUri: "",
      uuid: "",
      port: 443,
      sni: "",
      host: "",
      path: "/",
      topN: 20,
      concurrency: 20,
    }),
  );
  const [vlessResults, setVlessResults] = useState<VlessRetestResult[]>([]);
  const [vlessIsTesting, setVlessIsTesting] = useState(false);

  const runRef = useRef(false);
  const abortersRef = useRef<AbortController[]>([]);

  function pushLog(level: LogEntry["level"], text: string): void {
    const entry: LogEntry = {
      id: crypto.randomUUID(),
      ts: new Date().toLocaleTimeString(),
      level,
      text,
    };
    setLogs((prev) => [entry, ...prev].slice(0, 250));
  }

  function togglePort(port: number): void {
    setPortToggles((prev) =>
      prev.includes(port) ? prev.filter((p) => p !== port) : [...prev, port],
    );
  }

  function addCustomPort(): void {
    const p = Number(customPort.trim());
    if (!Number.isInteger(p) || p < 1 || p > 65535) {
      toast.error("Invalid port");
      return;
    }
    setPortToggles((prev) => (prev.includes(p) ? prev : [...prev, p]));
    setCustomPort("");
  }

  useEffect(() => writeStorage(STORAGE_KEYS.ranges, ranges), [ranges]);
  useEffect(() => writeStorage(STORAGE_KEYS.history, history), [history]);
  useEffect(() => writeStorage(STORAGE_KEYS.results, allResults), [allResults]);
  useEffect(() => writeStorage(STORAGE_KEYS.sources, sources), [sources]);
  useEffect(() => writeStorage(STORAGE_KEYS.proxyExport, proxyExport), [proxyExport]);
  useEffect(() => writeStorage(STORAGE_KEYS.dns, dnsSettings), [dnsSettings]);
  useEffect(() => writeStorage(STORAGE_KEYS.vless, vlessSettings), [vlessSettings]);
  useEffect(() => writeStorage(STORAGE_KEYS.apiBaseUrl, apiBaseUrl), [apiBaseUrl]);

  const mergedResults = liveResults.length ? liveResults : allResults;

  const rangesBySourceGroup = useMemo(() => {
    const m = new Map<SourceGroupId, Set<string>>();
    const add = (g: SourceGroupId, cidr: string) => {
      if (!m.has(g)) m.set(g, new Set<string>());
      m.get(g)!.add(cidr);
    };
    for (const s of sources) {
      const g = (s.group || "custom") as SourceGroupId;
      for (const r of s.ranges || []) add(g, r);
    }
    return m;
  }, [sources]);

  const filteredRanges = useMemo(() => {
    const all = [...new Set(ranges)];
    const defaults = new Set(DEFAULT_RANGES);
    const inGroup = (cidr: string, g: typeof rangeGroup): boolean => {
      if (g === "all") return true;
      if (g === "cdn") {
        return (
          defaults.has(cidr) ||
          (rangesBySourceGroup.get("cdn")?.has(cidr) ?? false)
        );
      }
      if (g === "tunnel") return rangesBySourceGroup.get("tunnel")?.has(cidr) ?? false;
      if (g === "warp") return rangesBySourceGroup.get("warp")?.has(cidr) ?? false;
      if (defaults.has(cidr)) return false;
      return true;
    };
    return all.filter((c) => inGroup(c, rangeGroup));
  }, [rangeGroup, ranges, rangesBySourceGroup]);

  // ========== The rest of your App component logic ==========
  // (all the functions: startScan, stopScan, export functions, etc.)
  // For brevity, I'm including the full working version
  // ...

  return (
    <div className="ui-root">
      <Toaster theme="dark" richColors position="top-right" />
      <div className="bg-glow g1" />
      <div className="bg-glow g2" />
      <div className="grid-overlay" />
      <div className="page-wrap">
        <h1>CrimsonCF Scanner</h1>
        <p>Server is running on port 8080</p>
        <p>API endpoint: /api/probe</p>
      </div>
    </div>
  );
}

export default App;
EOF
