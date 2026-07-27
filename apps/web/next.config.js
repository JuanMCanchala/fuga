/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // @fuga/core es un paquete del monorepo compilado a dist/. Lo transpilamos
  // para que Next lo empaquete sin problemas de resolución.
  transpilePackages: ['@fuga/core'],
  // La raíz sirve el sitio estático (hero animado + command center) sin cambiar
  // la URL. El command center llama a /api/analyze en el mismo origen.
  async rewrites() {
    return {
      beforeFiles: [{ source: '/', destination: '/site.html' }],
    };
  },
};

module.exports = nextConfig;
