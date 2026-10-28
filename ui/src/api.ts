import type { Snapshot } from "./types";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers || {}),
    },
  });
  const data = (await response.json()) as T & { reason?: string };
  if (!response.ok) {
    throw new Error(data.reason || `Request failed (${response.status})`);
  }
  return data;
}

export const api = {
  health: () => request<{ ok: boolean }>("/api/health"),
  snapshot: () => request<Snapshot>("/api/snapshot"),
  scan: () => request<{ ok: boolean; reason?: string }>("/api/scan", { method: "POST", body: "{}" }),
  refreshOui: () => request<{ ok: boolean }>("/api/oui/refresh", { method: "POST", body: "{}" }),
  ack: (id: number) => request("/api/alerts/ack", { method: "POST", body: JSON.stringify({ id }) }),
  meta: (body: { mac: string; trusted: boolean; owned: boolean; tags: string[]; notes: string }) =>
    request("/api/device/meta", { method: "POST", body: JSON.stringify(body) }),
  wol: (mac: string) => request<{ ok: boolean; reason?: string }>("/api/wol", { method: "POST", body: JSON.stringify({ mac }) }),
  traceroute: (host: string) => request("/api/traceroute", { method: "POST", body: JSON.stringify({ host }) }),
  dns: () => request("/api/dns", { method: "POST", body: "{}" }),
  nat: () => request("/api/nat", { method: "POST", body: "{}" }),
  speed: () => request("/api/speed", { method: "POST", body: "{}" }),
  wifi: () => request("/api/wifi", { method: "POST", body: "{}" }),
  local: () => request("/api/local", { method: "POST", body: "{}" }),
  upnp: () => request("/api/upnp", { method: "POST", body: "{}" }),
  dhcp: () => request("/api/dhcp", { method: "POST", body: "{}" }),
  snmp: (host: string, community: string) =>
    request("/api/snmp", { method: "POST", body: JSON.stringify({ host, community }) }),
  creds: (ip: string) => request("/api/creds", { method: "POST", body: JSON.stringify({ ip, confirm: true }) }),
  webhook: (url: string) => request("/api/webhook", { method: "POST", body: JSON.stringify({ url }) }),
  schedule: (minutes: number) => request("/api/schedule", { method: "POST", body: JSON.stringify({ minutes }) }),
  exportInventory: () => request("/api/export"),
  presence: (mac: string) => request<unknown[]>(`/api/presence?mac=${encodeURIComponent(mac)}`),
  ports: (ip: string | null, profile: string) =>
    request<{ ok: boolean; reason?: string }>("/api/ports", { method: "POST", body: JSON.stringify({ ip, profile }) }),
};

export function fmtRate(bps: number): string {
  if (!Number.isFinite(bps) || bps < 1) return "0 B/s";
  const units = ["B/s", "KB/s", "MB/s", "GB/s"];
  let value = bps;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return `${value.toFixed(value >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}
