/** @type {import('next').NextConfig} */
const nextConfig = {
  // Fully static site (HTML/JS/JSON on a CDN): no Next.js server runs in
  // production, so server-side advisories (image optimizer, server actions,
  // middleware) don't apply.
  output: 'export',
  images: { unoptimized: true },
  reactStrictMode: true,
};

export default nextConfig;
