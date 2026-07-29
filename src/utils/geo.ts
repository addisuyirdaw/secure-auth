export class GeoService {
  private static ipMap: Record<string, string> = {
    '127.0.0.1': 'Localhost',
    '::1': 'Localhost',
    '8.8.8.8': 'Mountain View, USA',
    '1.1.1.1': 'Sydney, Australia',
    '109.190.0.1': 'Paris, France',
    '203.0.113.1': 'Tokyo, Japan',
    '198.51.100.5': 'London, UK',
  };

  static lookupIp(ip: string): string {
    const cleanIp = ip.startsWith('::ffff:') ? ip.substring(7) : ip;
    return this.ipMap[cleanIp] || 'New York, USA';
  }
}
