// DNS
export interface DnsRecord {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

export interface DnsResponse {
  domain: string;
  type: string;
  records: DnsRecord[];
  queryTime: number;
}

// Email Auth
export type AuthStatus = 'pass' | 'warning' | 'fail';

export interface SpfResult {
  status: AuthStatus;
  record: string | null;
  details: string;
  recommendation: string;
}

export interface DmarcResult {
  status: AuthStatus;
  record: string | null;
  policy: string | null;
  details: string;
  recommendation: string;
}

export interface DkimResult {
  status: AuthStatus;
  record: string | null;
  selector: string;
  details: string;
  recommendation: string;
}

export interface EmailAuthResponse {
  domain: string;
  spf: SpfResult;
  dmarc: DmarcResult;
  dkim: DkimResult;
}

// CIDR
export interface CidrResult {
  network: string;
  broadcast: string;
  netmask: string;
  wildcardMask: string;
  firstHost: string;
  lastHost: string;
  totalHosts: number;
  usableHosts: number;
  cidr: number;
  ipClass: string;
  binary: string;
}

// GeoIP
export interface GeoIpResponse {
  ip: string;
  country: string;
  countryCode: string;
  region: string;
  city: string;
  lat: number;
  lon: number;
  isp: string;
  org: string;
  as: string;
  timezone: string;
}

// API Error
export interface ApiError {
  error: string;
}
