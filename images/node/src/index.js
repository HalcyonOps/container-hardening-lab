'use strict';

const express = require('express');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Health check — used by HEALTHCHECK in Dockerfile and by Kubernetes probes
app.get('/healthz', (_req, res) => {
  res.status(200).json({ status: 'ok' });
});

// Example resource endpoint
app.get('/api/items', (_req, res) => {
  res.json({ items: [] });
});

app.listen(PORT, '0.0.0.0', () => {
  // Use process.stdout to avoid console being flagged by linters
  process.stdout.write(`Server listening on port ${PORT}\n`);
});
