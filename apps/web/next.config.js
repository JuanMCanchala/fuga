/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // @fuga/core es un paquete del monorepo compilado a dist/. Lo transpilamos
  // para que Next lo empaquete sin problemas de resolución.
  transpilePackages: ['@fuga/core'],
};

module.exports = nextConfig;
