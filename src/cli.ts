#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { Store } from "./db.js";
import { PeService } from "./service.js";
import { startServer } from "./server.js";

const defaultDataDir = path.join(process.cwd(), "data");

function usage(): never {
  console.error(
    [
      "pe-inspect - offline PE32+ import table inspector",
      "",
      "Usage:",
      "  pe-inspect serve [--port N] [--data DIR]",
      "  pe-inspect import <file.pe> [--force] [--data DIR]",
      "  pe-inspect files [--data DIR]",
      "  pe-inspect summary <fileId> [--data DIR]",
      "  pe-inspect sections <fileId> [--data DIR]",
      "  pe-inspect imports <fileId> [--data DIR]",
      "  pe-inspect rva <fileId> <rva> [--data DIR]",
      "  pe-inspect reports [--data DIR]",
      "  pe-inspect export <reportId> [out.json] [--data DIR]",
    ].join("\n"),
  );
  process.exit(2);
}

function parseArgs(argv: string[]) {
  const pos: string[] = [];
  const opt: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--force") opt.force = true;
    else if (a === "--port") opt.port = argv[++i];
    else if (a === "--data") opt.data = argv[++i];
    else if (a.startsWith("--")) throw new Error(`Unknown option ${a}`);
    else pos.push(a);
  }
  return { pos, opt };
}

function parseRva(s: string): number {
  const n = s.toLowerCase().startsWith("0x") ? parseInt(s, 16) : parseInt(s, 10);
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(`Invalid RVA '${s}'`);
  return n;
}

async function main() {
  const { pos, opt } = parseArgs(process.argv.slice(2));
  const cmd = pos[0];
  if (!cmd) usage();
  const dataDir = typeof opt.data === "string" ? opt.data : defaultDataDir;
  const store = new Store(dataDir);
  const service = new PeService(store);
  const out = (x: unknown) => console.log(JSON.stringify(x, null, 2));

  try {
    switch (cmd) {
      case "serve": {
        const port = opt.port !== undefined ? Number(opt.port) : 0;
        if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error(`Invalid --port ${opt.port}`);
        const server = await startServer(service, port);
        const addr = server.address();
        const actual = typeof addr === "object" && addr ? addr.port : port;
        console.log(`pe-inspect listening on http://127.0.0.1:${actual} (data dir: ${dataDir})`);
        break;
      }
      case "import": {
        if (!pos[1]) usage();
        out(service.importFile(pos[1], opt.force === true));
        break;
      }
      case "files":
        out(store.listFiles());
        break;
      case "reports":
        out(store.listReports());
        break;
      case "summary":
        out(service.summary(Number(pos[1])));
        break;
      case "sections":
        out(service.sections(Number(pos[1])));
        break;
      case "imports":
        out(service.imports(Number(pos[1])));
        break;
      case "rva": {
        if (!pos[1] || !pos[2]) usage();
        out(service.explainRva(Number(pos[1]), parseRva(pos[2])));
        break;
      }
      case "export": {
        if (!pos[1]) usage();
        const report = service.exportReport(Number(pos[1]));
        if (pos[2]) {
          fs.writeFileSync(pos[2], JSON.stringify(report, null, 2));
          console.log(`Wrote ${pos[2]}`);
        } else {
          out(report);
        }
        break;
      }
      default:
        usage();
    }
  } catch (e: any) {
    console.error(`error[${e.code ?? "ERROR"}]: ${e.message}`);
    process.exitCode = 1;
  } finally {
    if (cmd !== "serve") store.close();
  }
}

main();
