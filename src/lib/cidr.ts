import type { CidrResult } from './types';

export function parseCidr(input: string): CidrResult | null {
  const match = input.trim().match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/);
  if (!match) return null;

  const ipStr = match[1];
  const cidr = parseInt(match[2], 10);

  if (cidr < 0 || cidr > 32) return null;

  const octets = ipStr.split('.').map(Number);
  if (octets.some(o => o < 0 || o > 255)) return null;

  const ipNum = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
  const mask = cidr === 0 ? 0 : (~0 << (32 - cidr)) >>> 0;
  const wildcard = (~mask) >>> 0;
  const network = (ipNum & mask) >>> 0;
  const broadcast = (network | wildcard) >>> 0;

  const totalHosts = Math.pow(2, 32 - cidr);
  const usableHosts = cidr >= 31 ? totalHosts : totalHosts - 2;

  const firstHost = cidr >= 31 ? network : (network + 1) >>> 0;
  const lastHost = cidr >= 31 ? broadcast : (broadcast - 1) >>> 0;

  return {
    network: numToIp(network),
    broadcast: numToIp(broadcast),
    netmask: numToIp(mask),
    wildcardMask: numToIp(wildcard),
    firstHost: numToIp(firstHost),
    lastHost: numToIp(lastHost),
    totalHosts,
    usableHosts,
    cidr,
    ipClass: getIpClass(octets[0]),
    binary: octets.map(o => o.toString(2).padStart(8, '0')).join('.'),
  };
}

function numToIp(num: number): string {
  return [
    (num >>> 24) & 255,
    (num >>> 16) & 255,
    (num >>> 8) & 255,
    num & 255,
  ].join('.');
}

function getIpClass(firstOctet: number): string {
  if (firstOctet < 128) return 'A';
  if (firstOctet < 192) return 'B';
  if (firstOctet < 224) return 'C';
  if (firstOctet < 240) return 'D (Multicast)';
  return 'E (Reservada)';
}
