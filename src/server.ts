import { createServer, IncomingMessage, ServerResponse, Server } from "node:http";
import { readFile } from "node:fs/promises";
import { resolve, isAbsolute } from "node:path";
import { InspectorService } from "./service.js";
import { PeError } from "./pe/errors.js";

function send(res: ServerResponse, status: number, body: unknown): void {
  const json = JSON.stringify(body, bigintReplacer);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  res.end(json);
}

function bigintReplacer(_key: string, value: unknown): unknown {
  return typeof value === "bigint" ? "0x" + value.toString(16) : value;
}

export function createApp(service: InspectorService): Server {
  return createServer(async (req: IncomingMessage, res: ServerResponse) => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      const path = url.pathname;
      const method = req.method ?? "GET";

      if (method === "POST" && path === "/api/imports") {
        let body = "";
        for await (const chunk of req) body += chunk;
        let payload: { path?: string };
        try {
          payload = JSON.parse(body || "{}");
        } catch {
          return send(res, 400, { error: { code: "BAD_REQUEST", message: "请求体不是合法 JSON" } });
        }
        if (!payload.path || typeof payload.path !== "string") {
          return send(res, 400, { error: { code: "BAD_REQUEST", message: "缺少字符串字段 path" } });
        }
        const abs = isAbsolute(payload.path) ? payload.path : resolve(process.cwd(), payload.path);
        const data = await readFile(abs);
        const result = service.importFromBuffer(baseName(abs), data);
        return send(res, result.duplicated ? 200 : 201, { duplicated: result.duplicated, report: result.report });
      }

      if (method === "GET" && path === "/api/reports") {
        return send(res, 200, { reports: service.list() });
      }

      const reportMatch = path.match(/^\/api\/reports\/(\d+)$/);
      if (method === "GET" && reportMatch) {
        const stored = service.get(Number(reportMatch[1]));
        return send(res, 200, stored);
      }

      const headerMatch = path.match(/^\/api\/reports\/(\d+)\/header$/);
      if (method === "GET" && headerMatch) {
        const stored = service.get(Number(headerMatch[1]));
        return send(res, 200, { header: stored.report.header });
      }

      const sectionsMatch = path.match(/^\/api\/reports\/(\d+)\/sections$/);
      if (method === "GET" && sectionsMatch) {
        const stored = service.get(Number(sectionsMatch[1]));
        return send(res, 200, { sections: stored.report.sections, warnings: stored.report.warnings });
      }

      const importsMatch = path.match(/^\/api\/reports\/(\d+)\/imports$/);
      if (method === "GET" && importsMatch) {
        const stored = service.get(Number(importsMatch[1]));
        return send(res, 200, {
          hasImportDirectory: stored.report.hasImportDirectory,
          unsupported: stored.report.unsupported,
          warnings: stored.report.warnings,
          imports: stored.report.imports,
        });
      }

      const mapMatch = path.match(/^\/api\/reports\/(\d+)\/map$/);
      if (method === "GET" && mapMatch) {
        const id = Number(mapMatch[1]);
        const rvaRaw = url.searchParams.get("rva");
        const lenRaw = url.searchParams.get("length") ?? "1";
        const rva = parseInteger(rvaRaw);
        const length = parseInteger(lenRaw);
        if (rva === null || rva < 0) return send(res, 400, { error: { code: "BAD_REQUEST", message: "rva 必须为非负整数（支持 0x 十六进制）" } });
        if (length === null || length < 1 || length > 16) return send(res, 400, { error: { code: "BAD_REQUEST", message: "length 取值范围 1..16" } });
        return send(res, 200, service.explainRva(id, rva, length));
      }

      return send(res, 404, { error: { code: "NOT_FOUND", message: `未知路由 ${method} ${path}` } });
    } catch (err) {
      if (err instanceof PeError) {
        const status = err.code === "INTERNAL" ? 404 : 422;
        return send(res, status, { error: err.toJSON() });
      }
      const e = err as NodeJS.ErrnoException;
      if (e.code === "ENOENT") return send(res, 404, { error: { code: "FILE_NOT_FOUND", message: e.message } });
      return send(res, 500, { error: { code: "INTERNAL", message: (err as Error).message } });
    }
  });
}

function parseInteger(raw: string | null): number | null {
  if (raw === null) return null;
  const t = raw.trim();
  if (/^0x[0-9a-fA-F]+$/.test(t)) return Number.parseInt(t, 16);
  if (/^\d+$/.test(t)) return Number.parseInt(t, 10);
  return null;
}

function baseName(p: string): string {
  return p.split(/[\\/]/).filter(Boolean).pop() ?? p;
}

export async function listen(server: Server, preferredPort?: number): Promise<{ port: number }> {
  const port = preferredPort ?? 0;
  await new Promise<void>((resolveFn, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolveFn());
  });
  const addr = server.address();
  if (!addr || typeof addr === "string") throw new Error("无法确定监听端口");
  return { port: addr.port };
}
