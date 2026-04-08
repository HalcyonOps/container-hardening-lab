// Deliberately minimal — exists only so the unhardened Dockerfile builds.
// This file is never run; it exists for the failure demo.
const http = require("http");
http.createServer((_, res) => { res.end("ok\n"); }).listen(80);
