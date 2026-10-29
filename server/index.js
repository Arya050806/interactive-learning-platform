import { createServer } from "node:http";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import { createDatabase } from "./db.js";
import { createApp } from "./app.js";

const serverDirectory = fileURLToPath(new URL(".", import.meta.url));
const db = createDatabase();
const app = createApp({ db });
const builtClient = resolve(serverDirectory, "../dist");

if (process.env.NODE_ENV === "production") {
  app.use(express.static(builtClient, { index: false, maxAge: "1h" }));
  app.get("*path", (_request, response) => response.sendFile(resolve(builtClient, "index.html")));
}

const server = createServer(app);
const port = Number(process.env.PORT ?? 3000);
server.listen(port, "127.0.0.1", () => {
  console.log(`MedLearn API listening on http://127.0.0.1:${port}`);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => server.close(() => {
    db.close();
    process.exit(0);
  }));
}
