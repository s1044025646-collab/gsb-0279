import http from "node:http";
import { PeService } from "./service.js";
import { PeError } from "./pe/errors.js";

function send(res: http.ServerResponse, status: number, body: unknown) {
  const json = JSON.stringify(body, null, 2);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  res.end(json);
}

function sendErr(res: http.ServerResponse, e: any) {
  if (e instanceof PeError) {
    send(res, 400, { error: { code: e.code, message: e.message, fileOffset: e.fileOffset, rva: e.rva?.toString() } });
  } else {
    send(res, 500, { error: { code: "INTERNAL", message: String(e?.message ?? e) } });
  }
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => {
      data += c;
      if (data.length > 1 << 20) reject(new PeError("VALIDATION", "Request body too large"));
    });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

function parseId(s: string | undefined, what: string): number {
  const n = Number(s);
  if (!Number.isInteger(n) || n <= 0) throw new PeError("VALIDATION", `Invalid ${what}: '${s}'`);
  return n;
}

export function createServer(service: PeService): http.Server {
  return http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      const parts = url.pathname.split("/").filter(Boolean);
      const method = req.method ?? "GET";

      if (method === "GET" && url.pathname === "/") {
        return send(res, 200, {
          service: "pe-inspect",
          endpoints: [
            "POST /files {path}",
            "GET /files",
            "GET /files/:id/summary",
            "GET /files/:id/sections",
            "GET /files/:id/imports",
            "GET /files/:id/rva?rva=0x2000",
            "GET /reports",
            "GET /reports/:id",
          ],
        });
      }

      if (method === "POST" && url.pathname === "/files") {
        const body = JSON.parse((await readBody(req)) || "{}");
        if (typeof body.path !== "string" || body.path.length === 0) {
          throw new PeError("VALIDATION", "Body must be JSON with a non-empty 'path' string");
        }
        return send(res, 201, service.importFile(body.path, body.force === true));
      }

      if (method === "GET" && url.pathname === "/files") {
        return send(res, 200, service.store.listFiles());
      }

      if (method === "GET" && url.pathname === "/reports") {
        return send(res, 200, service.store.listReports());
      }

      if (method === "GET" && parts[0] === "reports" && parts.length === 2) {
        return send(res, 200, service.exportReport(parseId(parts[1], "report id")));
      }

      if (method === "GET" && parts[0] === "files" && parts.length === 3) {
        const id = parseId(parts[1], "file id");
        switch (parts[2]) {
          case "summary":
            return send(res, 200, service.summary(id));
          case "sections":
            return send(res, 200, service.sections(id));
          case "imports":
            return send(res, 200, service.imports(id));
          case "rva": {
            const raw = url.searchParams.get("rva");
            if (!raw) throw new PeError("VALIDATION", "Missing query parameter 'rva' (decimal or 0x-hex)");
            const rva = raw.startsWith("0x") || raw.startsWith("0X") ? parseInt(raw, 16) : parseInt(raw, 10);
            if (!Number.isSafeInteger(rva) || rva < 0) throw new PeError("VALIDATION", `Invalid RVA '${raw}'`);
            return send(res, 200, service.explainRva(id, rva));
          }
        }
      }

      send(res, 404, { error: { code: "NOT_FOUND", message: `${method} ${url.pathname}` } });
    } catch (e) {
      sendErr(res, e);
    }
  });
}

/** Listen on the requested port; 0 (default) picks a free port. */
export function startServer(service: PeService, port = 0, host = "127.0.0.1"): Promise<http.Server> {
  const server = createServer(service);
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => resolve(server));
  });
}
