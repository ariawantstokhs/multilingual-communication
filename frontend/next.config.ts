import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /* config options here */
  output: 'export',
  basePath: '/multilingual-communication',
  trailingSlash: true,
  images: {
    unoptimized: true
  }
};

export default nextConfig;
