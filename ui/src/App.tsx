import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, fmtRate } from "./api";
import type { Device, Json, Snapshot } from "./types";

type Tab = "overview" | "alerts" | "connect" | "wifi" | "local" | "discover" | "settings";

const TABS: { id: Tab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "alerts", label: "Alerts" },
  { id: "connect", label: "Connectivity" },
  { id: "wifi", label: "Wi-Fi" },
  { id: "local", label: "This PC" },
  { id: "discover", label: "Discovery" },
  { id: "settings", label: "Settings" },
];

function asRecord(value: unknown): Json {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Json) : {};
}

function pretty(value: unknown): string {
  if (value == null || (typeof value === "object" && !Array.isArray(value) && !Object.keys(value as object).length)) {
    return "Nothing yet.";
  }
  return JSON.stringify(value, null, 2);
}

export default function App() {
  const [splash, setSplash] = useState(true);
  const [theme, setTheme] = useState<"dark" | "light">(() =>
    localStorage.getItem("netpulse-theme") === "light" ? "light" : "dark",
  );
  const [tab, setTab] = useState<Tab>("overview");
  const [snap, setSnap] = useState<Snapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("");
  const [profile, setProfile] = useState("common");
  const [autoScan, setAutoScan] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [rates, setRates] = useState<{ down: number; up: number }[]>([]);
  const [minutes, setMinutes] = useState(0);
  const [hook, setHook] = useState("");
  const [traceHost, setTraceHost] = useState("1.1.1.1");
  const [community, setCommunity] = useState("public");

  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
    localStorage.setItem("netpulse-theme", theme);
  }, [theme]);

  useEffect(() => {
    const timer = window.setTimeout(() => setSplash(false), 1400);
    return () => window.clearTimeout(timer);
  }, []);

  const refresh = useCallback(async () => {
    try {
      const next = await api.snapshot();
      setSnap(next);
      setError(null);
      setMinutes(Number(next.schedule_minutes || 0));
      setHook(next.webhook_url || "");
      const stats = next.stats || {};
      setRates((prev) => [...prev, { down: Number(stats.down_bps || 0), up: Number(stats.up_bps || 0) }].slice(-40));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Cannot reach the local API");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const id = window.setInterval(() => void refresh(), 1000);
    return () => window.clearInterval(id);
  }, [refresh]);

  useEffect(() => {
    void api.scan().catch(() => undefined);
  }, []);

  useEffect(() => {
    if (!autoScan) return;
    const id = window.setInterval(() => void api.scan().catch(() => undefined), 60000);
    return () => window.clearInterval(id);
  }, [autoScan]);

  const devices = snap?.devices || [];
  const stats = snap?.stats || {};
  const scan = snap?.scan || {};
  const extra = snap?.extra || {};
  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return devices;
    return devices.filter((d) => {
      const ports = (d.open_ports || []).map((p) => `${p.port} ${p.service || ""}`).join(" ");
      return [d.ip, d.mac, d.name, d.vendor, d.nature, d.role, ports, ...(d.tags || [])].join(" ").toLowerCase().includes(q);
    });
  }, [devices, filter]);

  const selectedDevice = devices.find((d) => d.ip === selected) || null;

  async function run(name: string, task: () => Promise<unknown>) {
    setBusy(name);
    setNotice(null);
    try {
      const result = await task();
      if (result && typeof result === "object" && "ok" in result && (result as { ok: boolean }).ok === false) {
        setNotice(String((result as { reason?: string }).reason || "Request was not started"));
      }
      await refresh();
    } catch (err) {
      setNotice(err instanceof Error ? err.message : "Action failed");
    } finally {
      setBusy(null);
    }
  }

  const progress = Number(scan.progress || 0);
  const total = Number(scan.total || 0);
  const pct = total ? Math.min(100, Math.round((progress / total) * 100)) : 0;
  const portMeta = snap?.port_meta || {};
  const portPct = Number(portMeta.total) ? Math.min(100, Math.round((Number(portMeta.progress) / Number(portMeta.total)) * 100)) : 0;

  return (
    <div className="min-h-screen bg-slate-100 text-slate-900 dark:bg-slate-950 dark:text-slate-100">
      {splash && (
        <div className="fixed inset-0 z-50 flex flex-col items-center justify-center gap-4 bg-slate-950 text-slate-100" role="status">
          <img src="./icon-192.png" alt="" className="h-20 w-20 rounded-2xl shadow-lg" />
          <h1 className="text-3xl tracking-wide">NetPulse</h1>
          <p className="text-sm text-slate-400">Starting the LAN analyzer</p>
          <div className="h-1 w-44 overflow-hidden rounded-full bg-slate-800" aria-hidden>
            <div className="h-full w-1/3 animate-pulse rounded-full bg-sky-400" />
          </div>
        </div>
      )}
      <header className="border-b border-slate-200/80 bg-white/80 backdrop-blur dark:border-white/10 dark:bg-slate-900/80">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-3 px-4 py-4">
          <img src="./icon-32.png" alt="" className="h-8 w-8 rounded-lg" />
          <div className="mr-auto">
            <p className="text-lg font-semibold tracking-tight">NetPulse</p>
            <p className="text-xs text-slate-500">Local LAN analyzer</p>
          </div>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={autoScan} onChange={(e) => setAutoScan(e.target.checked)} />
            Rescan every minute
          </label>
          <label className="text-sm">
            <span className="sr-only">Port profile</span>
            <select
              value={profile}
              onChange={(e) => setProfile(e.target.value)}
              className="rounded-full border border-slate-300 bg-transparent px-3 py-1.5 dark:border-white/15"
            >
              <option value="common">Common ports</option>
              <option value="extended">Extended ports</option>
            </select>
          </label>
          <button
            type="button"
            className="rounded-full bg-violet-600 px-4 py-1.5 text-sm text-white disabled:opacity-50"
            disabled={!!snap?.port_scanning || busy === "ports"}
            onClick={() => void run("ports", () => api.ports(null, profile))}
          >
            {snap?.port_scanning ? "Scanning ports…" : "Scan ports"}
          </button>
          <button
            type="button"
            className="rounded-full bg-sky-500 px-4 py-1.5 text-sm font-medium text-slate-950 disabled:opacity-50"
            disabled={!!snap?.scanning}
            onClick={() => void run("scan", () => api.scan())}
          >
            {snap?.scanning ? "Scanning…" : "Scan network"}
          </button>
          <button
            type="button"
            className="rounded-full border border-slate-300 px-3 py-1.5 text-sm dark:border-white/15"
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
          >
            {theme === "dark" ? "Light" : "Dark"}
          </button>
        </div>
        <nav className="mx-auto flex max-w-7xl gap-2 overflow-x-auto px-4 pb-3" aria-label="Sections">
          {TABS.map((item) => (
            <button
              key={item.id}
              type="button"
              role="tab"
              aria-selected={tab === item.id}
              className={`rounded-full px-4 py-1.5 text-sm ${tab === item.id ? "bg-sky-500 text-slate-950" : "bg-slate-200 text-slate-700 dark:bg-slate-800 dark:text-slate-300"}`}
              onClick={() => setTab(item.id)}
            >
              {item.label}
            </button>
          ))}
        </nav>
      </header>

      <main className="mx-auto max-w-7xl space-y-4 px-4 py-5">
        {error && (
          <div role="alert" className="rounded-2xl border border-rose-400/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-700 dark:text-rose-200">
            {error}
            <button type="button" className="ml-3 underline" onClick={() => void refresh()}>
              Retry
            </button>
          </div>
        )}
        {notice && (
          <p role="status" className="rounded-2xl border border-amber-400/40 bg-amber-500/10 px-4 py-3 text-sm">
            {notice}
          </p>
        )}

        {tab === "overview" && (
          <Overview
            loading={loading}
            stats={stats}
            scan={scan}
            oui={snap?.oui || {}}
            pct={pct}
            progress={progress}
            total={total}
            portPct={portPct}
            portMeta={portMeta}
            scanning={!!snap?.scanning}
            deviceCount={devices.length}
            rates={rates}
            filter={filter}
            setFilter={setFilter}
            rows={filtered}
            emptyBecauseFilter={devices.length > 0 && filtered.length === 0}
            onRefreshOui={() => void run("oui", () => api.refreshOui())}
            busy={busy}
            profile={profile}
            onPorts={(ip) => void run("ports", () => api.ports(ip, profile))}
            onSelect={setSelected}
            portScanning={!!snap?.port_scanning}
          />
        )}
        {tab === "alerts" && <Alerts alerts={snap?.alerts || []} outages={snap?.outages || []} onAck={(id) => void run("ack", () => api.ack(id))} />}
        {tab === "connect" && (
          <Connect
            extra={extra}
            history={snap?.speed_history || []}
            busy={busy}
            traceHost={traceHost}
            setTraceHost={setTraceHost}
            onNat={() => void run("nat", () => api.nat())}
            onDns={() => void run("dns", () => api.dns())}
            onTrace={() => void run("trace", () => api.traceroute(traceHost))}
            onSpeed={() => void run("speed", () => api.speed())}
          />
        )}
        {tab === "wifi" && <Wifi extra={extra} busy={busy} onScan={() => void run("wifi", () => api.wifi())} />}
        {tab === "local" && <Local extra={extra} busy={busy} onRefresh={() => void run("local", () => api.local())} />}
        {tab === "discover" && (
          <Discover
            extra={extra}
            busy={busy}
            community={community}
            setCommunity={setCommunity}
            onDhcp={() => void run("dhcp", () => api.dhcp())}
            onUpnp={() => void run("upnp", () => api.upnp())}
            onSnmp={() => void run("snmp", () => api.snmp("", community))}
          />
        )}
        {tab === "settings" && (
          <Settings
            minutes={minutes}
            setMinutes={setMinutes}
            hook={hook}
            setHook={setHook}
            busy={busy}
            onSchedule={() => void run("sched", () => api.schedule(minutes))}
            onHook={() => void run("hook", () => api.webhook(hook))}
            onExport={async () => {
              const data = await api.exportInventory();
              const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.href = url;
              a.download = "netpulse-inventory.json";
              a.click();
              URL.revokeObjectURL(url);
            }}
          />
        )}
      </main>

      {selectedDevice && (
        <DeviceDrawer
          key={selectedDevice.ip}
          device={selectedDevice}
          onClose={() => setSelected(null)}
          onSave={(body) => void run("meta", () => api.meta(body))}
          onWol={() => void run("wol", () => api.wol(selectedDevice.mac))}
          onCreds={() => {
            const ok = window.confirm(
              `Run a tiny default-password check on ${selectedDevice.ip}? Only use this on hardware you own. The device must be marked Owned.`,
            );
            if (!ok) return;
            void run("creds", () => api.creds(selectedDevice.ip));
          }}
        />
      )}
    </div>
  );
}

function Card({ title, children, action }: { title: string; children: ReactNode; action?: ReactNode }) {
  return (
    <section className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-white/10 dark:bg-slate-900">
      <div className="mb-2 flex items-center justify-between gap-2">
        <h2 className="text-sm font-medium">{title}</h2>
        {action}
      </div>
      {children}
    </section>
  );
}

function Overview(props: {
  loading: boolean;
  stats: Json;
  scan: Json;
  oui: Json;
  pct: number;
  progress: number;
  total: number;
  portPct: number;
  portMeta: Json;
  scanning: boolean;
  deviceCount: number;
  rates: { down: number; up: number }[];
  filter: string;
  setFilter: (v: string) => void;
  rows: Device[];
  emptyBecauseFilter: boolean;
  onRefreshOui: () => void;
  busy: string | null;
  profile: string;
  onPorts: (ip: string) => void;
  onSelect: (ip: string) => void;
  portScanning: boolean;
}) {
  const max = Math.max(1, ...props.rates.flatMap((r) => [r.down, r.up]));
  const line = (key: "down" | "up") =>
    props.rates
      .map((r, i) => {
        const x = props.rates.length < 2 ? 0 : (i / (props.rates.length - 1)) * 100;
        const y = 36 - (r[key] / max) * 32;
        return `${x},${y}`;
      })
      .join(" ");
  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {[
          ["This PC", String(props.stats.local_ip || "—"), String(props.stats.hostname || "")],
          ["Gateway", String(props.stats.gateway || "—"), String(props.stats.cidr || "")],
          ["Download", fmtRate(Number(props.stats.down_bps || 0)), ""],
          ["Upload", fmtRate(Number(props.stats.up_bps || 0)), String(props.stats.iface || "")],
        ].map(([label, value, sub]) => (
          <Card key={label} title={label}>
            <p className="font-mono text-xl">{props.loading ? "…" : value}</p>
            <p className="mt-1 text-xs text-slate-500">{sub}</p>
          </Card>
        ))}
      </div>
      <div className="grid gap-3 lg:grid-cols-3">
        <Card title="Throughput">
          <svg viewBox="0 0 100 40" className="h-36 w-full" role="img" aria-label="Network throughput">
            <polyline fill="none" stroke="#34d399" strokeWidth="1.5" points={line("down")} />
            <polyline fill="none" stroke="#a78bfa" strokeWidth="1.5" points={line("up")} />
          </svg>
        </Card>
        <Card title="Scan">
          <p className="text-sm">{props.scanning ? "Scanning the LAN" : props.scan.error ? String(props.scan.error) : "Idle"}</p>
          <div className="mt-3 h-2 overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800">
            <div className="h-full bg-sky-400" style={{ width: `${props.pct}%` }} />
          </div>
          <p className="mt-2 font-mono text-xs text-slate-500">
            {props.progress} / {props.total} hosts · {String(props.scan.method || "—")} · last {String(props.scan.last_scan || "—")}
          </p>
          <div className="mt-3 h-2 overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800">
            <div className="h-full bg-violet-400" style={{ width: `${props.portPct}%` }} />
          </div>
          <p className="mt-2 font-mono text-xs text-slate-500">
            Ports {String(props.portMeta.progress || 0)} / {String(props.portMeta.total || 0)}
            {props.portMeta.current_ip ? ` · ${String(props.portMeta.current_ip)}` : ""}
            {props.portMeta.error ? ` · ${String(props.portMeta.error)}` : ""}
          </p>
        </Card>
        <Card
          title="OUI database"
          action={
            <button type="button" className="text-xs text-sky-600 dark:text-sky-300" onClick={props.onRefreshOui} disabled={props.busy === "oui"}>
              Refresh OUI
            </button>
          }
        >
          <p className="text-sm">
            {String(props.oui.error || (props.oui.ready ? "OUI index ready" : "Loading IEEE / Wireshark feeds…"))}
          </p>
          <p className="mt-1 text-xs text-slate-500">
            {props.oui.entries != null ? `${String(props.oui.entries)} prefixes` : "prefixes pending"}
            {props.oui.source ? ` · ${String(props.oui.source)}` : ""}
            {props.oui.updated_label ? ` · ${String(props.oui.updated_label)}` : ""}
          </p>
          <p className="mt-3 text-sm">{props.deviceCount} devices on the last sweep</p>
        </Card>
      </div>
      <Card title="Devices">
        <label className="mb-3 block text-sm">
          <span className="sr-only">Filter devices</span>
          <input
            value={props.filter}
            onChange={(e) => props.setFilter(e.target.value)}
            placeholder="Filter by IP, MAC, name…"
            className="w-full rounded-xl border border-slate-300 bg-transparent px-3 py-2 dark:border-white/10"
          />
        </label>
        {props.loading ? (
          <div className="space-y-2" aria-busy="true">
            <div className="h-10 animate-pulse rounded-xl bg-slate-200 dark:bg-slate-800" />
            <div className="h-10 animate-pulse rounded-xl bg-slate-200 dark:bg-slate-800" />
          </div>
        ) : props.rows.length === 0 ? (
          <p className="py-10 text-center text-sm text-slate-500">
            {props.emptyBecauseFilter ? "No devices match this filter." : "Scan the network to discover devices on this LAN."}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-slate-500">
                <tr>
                  <th className="px-2 py-2">IP</th>
                  <th className="px-2 py-2">MAC</th>
                  <th className="px-2 py-2">Name</th>
                  <th className="px-2 py-2">Vendor</th>
                  <th className="px-2 py-2">Nature</th>
                  <th className="px-2 py-2">Role</th>
                  <th className="px-2 py-2">Ports</th>
                  <th className="px-2 py-2" />
                </tr>
              </thead>
              <tbody>
                {props.rows.map((d) => (
                  <tr key={d.ip} className="border-t border-slate-100 dark:border-white/5">
                    <td className="px-2 py-2 font-mono">{d.ip}</td>
                    <td className="px-2 py-2 font-mono text-xs">{d.mac}</td>
                    <td className="px-2 py-2">{d.name}</td>
                    <td className="px-2 py-2">
                      <div>{d.vendor || "Unknown"}</div>
                      <div className="text-[0.7rem] text-slate-500">{d.oui_source || "no OUI hit"}</div>
                    </td>
                    <td className="px-2 py-2" title={d.nature_note || ""}>
                      {d.nature}
                    </td>
                    <td className="px-2 py-2">{d.role}</td>
                    <td className="px-2 py-2">
                      <PortList device={d} />
                      {d.risk && (
                        <div className="text-[0.7rem] text-slate-500">
                          Risk {d.risk.score} {d.risk.grade}
                        </div>
                      )}
                      {d.http?.title && <div className="text-[0.7rem] text-slate-500">HTTP: {d.http.title}</div>}
                      {d.tls?.cn && (
                        <div className="text-[0.7rem] text-slate-500">
                          TLS CN {d.tls.cn}
                          {d.tls.self_signed ? " (self-signed)" : ""}
                        </div>
                      )}
                    </td>
                    <td className="px-2 py-2 text-right">
                      <button type="button" className="mr-2 text-xs text-violet-600 dark:text-violet-300" disabled={props.portScanning} onClick={() => props.onPorts(d.ip)}>
                        Ports
                      </button>
                      <button type="button" className="text-xs text-sky-600 dark:text-sky-300" onClick={() => props.onSelect(d.ip)}>
                        Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="mt-2 text-xs text-slate-500">Profile for new port scans: {props.profile}. Subnets wider than /24 stay capped.</p>
      </Card>
    </div>
  );
}

function PortList({ device }: { device: Device }) {
  const ports = device.open_ports || [];
  if (device.port_scan_state === "queued") return <span className="text-xs text-violet-500">Queued…</span>;
  if (!ports.length) return <span className="text-xs text-slate-500">{device.port_scan_state === "done" ? "None open" : "Not scanned"}</span>;
  return (
    <div className="flex max-w-xs flex-wrap gap-1">
      {ports.map((p) => (
        <span key={p.port} className="rounded-full bg-sky-500/10 px-2 py-0.5 font-mono text-[0.7rem]" title={p.banner || p.service}>
          {p.port} {p.service}
        </span>
      ))}
    </div>
  );
}

function Alerts({ alerts, outages, onAck }: { alerts: Json[]; outages: Json[]; onAck: (id: number) => void }) {
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      <Card title="Alerts">
        {alerts.length === 0 ? (
          <p className="text-sm text-slate-500">No alerts yet. New devices, ARP changes, and outages land here.</p>
        ) : (
          <ul className="space-y-2">
            {alerts.map((a) => (
              <li key={String(a.id)} className="flex items-start justify-between gap-3 rounded-xl bg-slate-50 px-3 py-2 text-sm dark:bg-slate-800/60">
                <div>
                  <p className="font-medium">
                    {String(a.severity || "")} · {String(a.title || "")}
                  </p>
                  <p className="text-xs text-slate-500">{String(a.detail || "")}</p>
                </div>
                {!a.acked && (
                  <button type="button" className="text-xs text-sky-600" onClick={() => onAck(Number(a.id))}>
                    Ack
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card title="Outages">
        {outages.length === 0 ? (
          <p className="text-sm text-slate-500">No recorded outages.</p>
        ) : (
          <ul className="space-y-2 font-mono text-xs">
            {outages.map((o, i) => (
              <li key={i}>{pretty(o)}</li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

function Connect(props: {
  extra: Json;
  history: Json[];
  busy: string | null;
  traceHost: string;
  setTraceHost: (v: string) => void;
  onNat: () => void;
  onDns: () => void;
  onTrace: () => void;
  onSpeed: () => void;
}) {
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        <button type="button" className="rounded-full bg-sky-500/20 px-4 py-2 text-sm" disabled={props.busy === "nat"} onClick={props.onNat}>
          Public IP / NAT
        </button>
        <button type="button" className="rounded-full bg-sky-500/20 px-4 py-2 text-sm" disabled={props.busy === "dns"} onClick={props.onDns}>
          DNS check
        </button>
        <label className="flex items-center gap-2 text-sm">
          Traceroute
          <input value={props.traceHost} onChange={(e) => props.setTraceHost(e.target.value)} className="w-36 rounded-full border border-slate-300 bg-transparent px-3 py-1 dark:border-white/15" />
        </label>
        <button type="button" className="rounded-full bg-sky-500/20 px-4 py-2 text-sm" disabled={props.busy === "trace"} onClick={props.onTrace}>
          Run traceroute
        </button>
        <button type="button" className="rounded-full bg-violet-500/20 px-4 py-2 text-sm" disabled={props.busy === "speed"} onClick={props.onSpeed}>
          Speed + bufferbloat
        </button>
      </div>
      <div className="grid gap-3 lg:grid-cols-2">
        <Card title="Ping">{props.busy === "nat" ? <Skeleton /> : <Pre value={props.extra.ping} />}</Card>
        <Card title="NAT / IPv6">{props.busy === "nat" ? <Skeleton /> : <Pre value={{ nat: props.extra.nat, ipv6: props.extra.ipv6 }} />}</Card>
        <Card title="DNS">{props.busy === "dns" ? <Skeleton /> : <Pre value={props.extra.dns} />}</Card>
        <Card title="Traceroute">{props.busy === "trace" ? <Skeleton /> : <Pre value={props.extra.traceroute} />}</Card>
        <Card title="Speed">
          {props.busy === "speed" ? <Skeleton /> : <Pre value={props.extra.speed} />}
          <ul className="mt-2 space-y-1 font-mono text-xs text-slate-500">
            {props.history.length === 0 && <li>No saved speed samples.</li>}
            {props.history.map((row, i) => (
              <li key={i}>{pretty(row)}</li>
            ))}
          </ul>
        </Card>
      </div>
    </div>
  );
}

function Wifi({ extra, busy, onScan }: { extra: Json; busy: string | null; onScan: () => void }) {
  const wifi = asRecord(extra.wifi);
  const networks = Array.isArray(wifi.networks) ? wifi.networks : [];
  const rows = networks.map((item) => {
    const net = asRecord(item);
    const first = asRecord(Array.isArray(net.bssids) ? net.bssids[0] : {});
    return {
      ssid: String(net.ssid || "(hidden)"),
      auth: String(net.auth || ""),
      encryption: String(net.encryption || ""),
      signal: String(first.signal || ""),
      channel: String(first.channel || ""),
      bssid: String(first.bssid || ""),
    };
  });
  return (
    <div className="space-y-3">
      <button type="button" className="rounded-full bg-sky-500 px-4 py-2 text-sm font-medium text-slate-950" disabled={busy === "wifi"} onClick={onScan}>
        {busy === "wifi" ? "Scanning…" : "Scan Wi-Fi neighbors"}
      </button>
      {busy === "wifi" ? (
        <Skeleton />
      ) : rows.length === 0 ? (
        <Card title="Neighbors">
          <p className="text-sm text-slate-500">No neighbor scan yet. {wifi.reason ? String(wifi.reason) : ""}</p>
        </Card>
      ) : (
        <Card title="Neighbors">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-slate-500">
                <tr>
                  {["SSID", "Auth", "Encryption", "Signal", "Channel", "BSSID"].map((key) => (
                    <th key={key} className="px-2 py-2">{key}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={`${row.ssid}-${row.bssid}`} className="border-t border-slate-100 dark:border-white/5">
                    <td className="px-2 py-2">{row.ssid}</td>
                    <td className="px-2 py-2">{row.auth}</td>
                    <td className="px-2 py-2">{row.encryption}</td>
                    <td className="px-2 py-2 font-mono text-xs">{row.signal}</td>
                    <td className="px-2 py-2 font-mono text-xs">{row.channel}</td>
                    <td className="px-2 py-2 font-mono text-xs">{row.bssid}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}

function Local({ extra, busy, onRefresh }: { extra: Json; busy: string | null; onRefresh: () => void }) {
  const local = asRecord(extra.local);
  return (
    <div className="space-y-3">
      <button type="button" className="rounded-full bg-sky-500/20 px-4 py-2 text-sm" onClick={onRefresh} disabled={busy === "local"}>
        Refresh this PC
      </button>
      {busy === "local" ? (
        <Skeleton />
      ) : Object.keys(local).length === 0 ? (
        <p className="text-sm text-slate-500">Waiting for the local NIC and process sample.</p>
      ) : (
        <div className="grid gap-3 lg:grid-cols-2">
          <Card title="Report"><Pre value={local} /></Card>
        </div>
      )}
    </div>
  );
}

function Discover(props: {
  extra: Json;
  busy: string | null;
  community: string;
  setCommunity: (v: string) => void;
  onDhcp: () => void;
  onUpnp: () => void;
  onSnmp: () => void;
}) {
  const topo = asRecord(props.extra.topology);
  const nodes = Array.isArray(topo.nodes) ? topo.nodes : [];
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" className="rounded-full bg-amber-500/20 px-4 py-2 text-sm" disabled={props.busy === "dhcp"} onClick={props.onDhcp}>DHCP / rogue probe</button>
        <button type="button" className="rounded-full bg-violet-500/20 px-4 py-2 text-sm" disabled={props.busy === "upnp"} onClick={props.onUpnp}>UPnP IGD forwards</button>
        <label className="text-sm">
          SNMP community
          <input value={props.community} onChange={(e) => props.setCommunity(e.target.value)} className="ml-2 w-28 rounded-full border border-slate-300 bg-transparent px-3 py-1 dark:border-white/15" />
        </label>
        <button type="button" className="rounded-full bg-sky-500/20 px-4 py-2 text-sm" disabled={props.busy === "snmp"} onClick={props.onSnmp}>SNMP gateway</button>
      </div>
      <Card title="L3 topology">
        <p className="text-xs text-slate-500">{String(topo.honest || "Run a scan to draw internet → gateway → hosts.")}</p>
        {nodes.length === 0 ? (
          <p className="mt-3 text-sm text-slate-500">No topology yet.</p>
        ) : (
          <div className="mt-3 flex flex-wrap gap-2">
            {nodes.map((node) => (
              <span key={String(asRecord(node).id)} className="rounded-full bg-slate-100 px-3 py-1 text-xs dark:bg-slate-800">
                {String(asRecord(node).label || asRecord(node).id)}
              </span>
            ))}
          </div>
        )}
      </Card>
      <div className="grid gap-3 lg:grid-cols-2">
        <Card title="mDNS / SSDP / DHCP"><Pre value={{ mdns: props.extra.mdns, ssdp: props.extra.ssdp, dhcp: props.extra.dhcp, dhcp_fp: props.extra.dhcp_fp }} /></Card>
        <Card title="UPnP and SNMP"><Pre value={{ upnp: props.extra.upnp_maps, snmp: props.extra.snmp }} /></Card>
      </div>
    </div>
  );
}

function Settings(props: {
  minutes: number;
  setMinutes: (n: number) => void;
  hook: string;
  setHook: (v: string) => void;
  busy: string | null;
  onSchedule: () => void;
  onHook: () => void;
  onExport: () => Promise<void>;
}) {
  return (
    <Card title="Schedule, webhook, export">
      <div className="grid gap-3 md:grid-cols-2">
        <label className="text-sm">
          Rescan interval (minutes, 0 off)
          <input
            type="number"
            min={0}
            max={1440}
            value={props.minutes}
            onChange={(e) => props.setMinutes(Number(e.target.value))}
            className="mt-1 w-full rounded-xl border border-slate-300 bg-transparent px-3 py-2 dark:border-white/10"
          />
        </label>
        <label className="text-sm">
          Webhook URL
          <input
            type="url"
            value={props.hook}
            onChange={(e) => props.setHook(e.target.value)}
            placeholder="https://"
            className="mt-1 w-full rounded-xl border border-slate-300 bg-transparent px-3 py-2 dark:border-white/10"
          />
        </label>
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        <button type="button" className="rounded-full bg-sky-500 px-4 py-2 text-sm text-slate-950" disabled={props.busy === "sched"} onClick={props.onSchedule}>Save schedule</button>
        <button type="button" className="rounded-full bg-violet-500/30 px-4 py-2 text-sm" disabled={props.busy === "hook"} onClick={props.onHook}>Save webhook</button>
        <button type="button" className="rounded-full border border-slate-300 px-4 py-2 text-sm dark:border-white/10" onClick={() => void props.onExport()}>Download JSON export</button>
      </div>
    </Card>
  );
}

function DeviceDrawer({
  device,
  onClose,
  onSave,
  onWol,
  onCreds,
}: {
  device: Device;
  onClose: () => void;
  onSave: (body: { mac: string; trusted: boolean; owned: boolean; tags: string[]; notes: string }) => void;
  onWol: () => void;
  onCreds: () => void;
}) {
  const mac = device.store_mac || device.mac;
  const [trusted, setTrusted] = useState(!!device.trusted);
  const [owned, setOwned] = useState(!!device.owned);
  const [tags, setTags] = useState((device.tags || []).join(", "));
  const [notes, setNotes] = useState(device.notes || "");
  const [history, setHistory] = useState<string>("Loading…");

  useEffect(() => {
    void api.presence(mac).then((rows) => setHistory(pretty(rows))).catch((err: Error) => setHistory(err.message));
  }, [mac]);

  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-slate-950/40" role="presentation" onClick={onClose}>
      <aside
        role="dialog"
        aria-label={`Device ${device.ip}`}
        className="h-full w-full max-w-md overflow-y-auto bg-white p-5 shadow-xl dark:bg-slate-900"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-4 flex items-start justify-between">
          <div>
            <h2 className="text-lg font-semibold">{device.name || device.ip}</h2>
            <p className="font-mono text-xs text-slate-500">{device.ip} · {device.mac}</p>
          </div>
          <button type="button" className="rounded-full border px-3 py-1 text-sm" onClick={onClose}>Close</button>
        </div>
        <p className="text-sm">{device.nature}</p>
        <p className="mt-1 text-xs text-slate-500">{device.nature_note}</p>
        <div className="mt-4 space-y-3 text-sm">
          <label className="flex items-center gap-2"><input type="checkbox" checked={owned} onChange={(e) => setOwned(e.target.checked)} /> Owned</label>
          <label className="flex items-center gap-2"><input type="checkbox" checked={trusted} onChange={(e) => setTrusted(e.target.checked)} /> Trusted</label>
          <label className="block">Tags
            <input value={tags} onChange={(e) => setTags(e.target.value)} className="mt-1 w-full rounded-xl border border-slate-300 bg-transparent px-3 py-2 dark:border-white/10" />
          </label>
          <label className="block">Notes
            <textarea value={notes} onChange={(e) => setNotes(e.target.value)} className="mt-1 w-full rounded-xl border border-slate-300 bg-transparent px-3 py-2 dark:border-white/10" rows={3} />
          </label>
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          <button
            type="button"
            className="rounded-full bg-sky-500 px-4 py-2 text-sm text-slate-950"
            onClick={() =>
              onSave({
                mac,
                trusted,
                owned,
                tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
                notes,
              })
            }
          >
            Save
          </button>
          <button type="button" className="rounded-full border px-4 py-2 text-sm" onClick={onWol}>Wake-on-LAN</button>
          <button type="button" className="rounded-full border border-amber-400/50 px-4 py-2 text-sm text-amber-700 dark:text-amber-200" onClick={onCreds}>
            Default creds
          </button>
        </div>
        <h3 className="mt-6 text-sm font-medium">Presence</h3>
        <pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap font-mono text-xs text-slate-600 dark:text-slate-300">{history || "Loading…"}</pre>
      </aside>
    </div>
  );
}

function Pre({ value }: { value: unknown }) {
  return <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap font-mono text-xs text-slate-600 dark:text-slate-300">{pretty(value)}</pre>;
}

function Skeleton() {
  return <div className="h-24 animate-pulse rounded-xl bg-slate-200 dark:bg-slate-800" aria-busy="true" />;
}
