import type { NextConfig } from 'next';

const gatewayInternalUrl = (process.env.GATEWAY_INTERNAL_URL || 'http://127.0.0.1:8081').replace(/\/+$/, '');

const nextConfig: NextConfig = {
  reactStrictMode: true,
  experimental: {
    // Uploads use a dedicated streamed route, but retain a compatible ceiling
    // for any Next.js proxy path used by a deployment.
    proxyClientMaxBodySize: '512mb',
    proxyTimeout: 300_000,
  },
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: `${gatewayInternalUrl}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
