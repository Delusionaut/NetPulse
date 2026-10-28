export type Json = Record<string, unknown>;

export interface PortHit {
  port: number;
  service?: string;
  banner?: string;
}

export interface Device {
  ip: string;
  mac: string;
  name?: string;
  vendor?: string;
  oui_source?: string;
  oui_prefix?: string;
  nature?: string;
  nature_note?: string;
  confidence?: string;
  role?: string;
  is_self?: boolean;
  is_gateway?: boolean;
  open_ports?: PortHit[];
  port_scan_state?: string;
  risk?: { score?: number; grade?: string; findings?: string[] };
  http?: { title?: string };
  tls?: { cn?: string; self_signed?: boolean };
  mdns?: { services?: string[]; names?: string[] };
  ssdp?: { friendly_name?: string; model?: string };
  netbios?: string;
  trusted?: boolean;
  owned?: boolean;
  tags?: string[];
  notes?: string;
  store_mac?: string;
  first_seen?: number | null;
  last_seen?: number | null;
}

export interface Snapshot {
  devices: Device[];
  stats: Json;
  scanning: boolean;
  scan: Json;
  oui: Json;
  port_scanning: boolean;
  port_meta: Json;
  extra: Json;
  alerts: Json[];
  outages: Json[];
  speed_history: Json[];
  webhook_url?: string;
  schedule_minutes?: number;
}
