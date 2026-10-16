import { describe, it, expect } from 'vitest';
import { isBlockedIp, checkUrlSyntax, assertPublicUrl, parseIPv6 } from '../src/lib/url-guard';

describe('isBlockedIp', () => {
  it.each([
    '127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1',
    '0.0.0.0', '224.0.0.1', '255.255.255.255', '::1', '::', 'fe80::1', 'fc00::1', 'fd00:ec2::254',
    '::ffff:127.0.0.1', '::ffff:10.0.0.1', '64:ff9b::a00:1', '2001:db8::1', 'ff02::1',
  ])('blocks %s', (ip) => expect(isBlockedIp(ip)).toBe(true));
  it.each(['8.8.8.8', '1.1.1.1', '172.32.0.1', '100.128.0.1', '2606:4700:4700::1111', '::ffff:8.8.8.8'])('allows %s', (ip) =>
    expect(isBlockedIp(ip)).toBe(false),
  );
  it('parses IPv6 forms', () => {
    expect(parseIPv6('2001:db8::1')).toEqual([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
    expect(parseIPv6('1:2:3')).toBeNull();
  });
});

describe('checkUrlSyntax', () => {
  it.each([
    'ftp://example.com', 'file:///etc/passwd', 'http://example.com:8080', 'http://127.0.0.1', 'http://2130706433/',
    'http://0x7f.0.0.1', 'http://[::1]/', 'http://169.254.169.254/latest/meta-data', 'http://localhost', 'http://foo.internal', 'http://intranet',
  ])('rejects %s', (u) => expect(() => checkUrlSyntax(u)).toThrow());
  it('accepts and normalizes public URLs', () => {
    expect(checkUrlSyntax('example.com').toString()).toBe('https://example.com/');
    expect(checkUrlSyntax('http://user:pw@example.com:443/x').toString()).toBe('http://example.com:443/x');
  });
});

describe('assertPublicUrl', () => {
  it('blocks hostnames resolving to private IPs', async () => {
    await expect(assertPublicUrl('https://evil.example', async () => ['93.184.216.34', '10.0.0.5'])).rejects.toThrow(/privada/);
  });
  it('allows public resolution', async () => {
    await expect(assertPublicUrl('https://ok.example', async () => ['93.184.216.34'])).resolves.toBeInstanceOf(URL);
  });
  it('rejects names without records', async () => {
    await expect(assertPublicUrl('https://none.example', async () => [])).rejects.toThrow();
  });
});
