#!/usr/bin/env node
import { startMcpServer } from './server.js';

startMcpServer().catch((err) => {
  console.error('FUGA MCP falló al iniciar:', err);
  process.exit(1);
});
