#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve, isAbsolute, join } from "node:path";
import { ReportStore } from "../db.js";
import { InspectorService } from "../service.js";
import { createApp, listen } from "../server.js";
import { PeError } from "../pe/errors.js";
import type { ImportedDll } from "../pe/types.js";

interface ParsedArgs {
  command: string;
  positional: string[];
  flags: Record<string, string | boolean>;
}

function parseArgs(argv: string[]): ParsedArgs {
  const [command = "", ...rest] = argv;
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!;
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = rest[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(a);
    }
  }
  return { command, positional, flags };
}

function dataDir(flags: Record<string, string | boolean>): string {
  const dir = typeof flags["data-dir"] === "string" ? flags["data-dir"] : join(process.cwd(), "data");
  mkdirSync(dir, { recursive: true });
  return dir;
}

function parseIntArg(v: string | undefined, name: string): number {
  if (v === undefined) throw new PeError("INTERNAL", `缺少参数 --${name}`);
  const t = v.trim();
  let n: number;
  if (/^0x[0-9a-fA-F]+$/.test(t)) n = Number.parseInt(t, 16);
  else if (/^\d+$/.test(t)) n = Number.parseInt(t, 10);
  else throw new PeError("INTERNAL", `--${name} 必须是整数（支持 0x 前缀）`);
  return n;
}

function outJson(value: unknown): void {
  process.stdout.write(JSON.stringify(value, bigintReplacer, 2) + "\n");
}

function bigintReplacer(_k: string, v: unknown): unknown {
  return typeof v === "bigint" ? "0x" + v.toString(16) : v;
}

function printImports(dlls: ImportedDll[]): void {
  if (dlls.length === 0) {
    console.log("（无导入表，或导入目录为空——这是合法状态）");
    return;
  }
  for (const dll of dlls) {
    console.log(`\nDLL: ${dll.name}`);
    console.log(`  名称RVA=0x${dll.nameRva.toString(16)}  thunk来源=${dll.usedThunk}  OFT=0x${dll.originalFirstThunk.toString(16)} FT=0x${dll.firstThunk.toString(16)}`);
    for (const fn of dll.functions) {
      if (fn.name !== null) {
        console.log(`  [hint=${fn.hint}] ${fn.name}    thunkRVA=0x${fn.thunkRva.toString(16)} 名称偏移=0x${(fn.sourceFileOffset ?? 0).toString(16)}${fn.viaFallback ? " (回退)" : ""}`);
      } else {
        console.log(`  Ordinal #${fn.ordinal}    thunkRVA=0x${fn.thunkRva.toString(16)} thunk偏移=0x${(fn.sourceFileOffset ?? 0).toString(16)}${fn.viaFallback ? " (回退)" : ""}`);
      }
    }
  }
}

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));
  const dir = dataDir(args.flags);
  const store = new ReportStore(dir);
  const service = new InspectorService(store);

  try {
    switch (args.command) {
      case "import": {
        const p = args.positional[0];
        if (!p) throw new PeError("INTERNAL", "用法: import <pe 文件路径> [--name 名称]");
        const abs = isAbsolute(p) ? p : resolve(process.cwd(), p);
        if (!existsSync(abs)) throw new PeError("INTERNAL", `文件不存在: ${abs}`);
        const result = service.importFromBuffer(String(args.flags.name ?? baseName(abs)), readFileSync(abs));
        console.log(`${result.duplicated ? "已存在（重复导入，未新建）" : "导入成功"}  report id=${result.report.id}  sha256=${result.report.sha256}`);
        return 0;
      }
      case "reports": {
        outJson({ parserVersion: store.parserVersion(), reports: service.list() });
        return 0;
      }
      case "header": {
        const id = parseIntArg(args.positional[0], "id");
        outJson(service.get(id).report.header);
        return 0;
      }
      case "sections": {
        const id = parseIntArg(args.positional[0], "id");
        outJson({ sections: service.get(id).report.sections, warnings: service.get(id).report.warnings });
        return 0;
      }
      case "imports": {
        const id = parseIntArg(args.positional[0], "id");
        const report = service.get(id).report;
        if (args.flags.json) {
          outJson({ hasImportDirectory: report.hasImportDirectory, imports: report.imports, unsupported: report.unsupported, warnings: report.warnings });
        } else {
          console.log(`文件 ${report.fileName} (${report.fileSize} 字节) parser=${report.parserVersion}`);
          if (report.unsupported.length) console.log("不支持项:", report.unsupported.join(", "));
          printImports(report.imports);
        }
        return 0;
      }
      case "map": {
        const id = parseIntArg(args.positional[0], "id");
        const rva = parseIntArg(args.positional[1], "rva");
        const length = args.positional[2] !== undefined ? parseIntArg(args.positional[2], "length") : 1;
        const result = service.explainRva(id, rva, length);
        if (args.flags.json) {
          outJson(result);
        } else {
          console.log(result.steps.join("\n"));
          console.log(result.mappable ? `=> 文件偏移 0x${(result.fileOffset ?? 0).toString(16)}（节: ${result.sectionName ?? result.region}）` : `=> 无法映射: ${result.reason}`);
        }
        return result.mappable ? 0 : 2;
      }
      case "export": {
        const id = parseIntArg(args.positional[0], "id");
        const target = args.positional[1];
        const json = JSON.stringify(service.get(id).report, bigintReplacer, 2);
        if (target) writeFileSync(target, json, "utf8"), console.log(`已导出到 ${target}`);
        else process.stdout.write(json + "\n");
        return 0;
      }
      case "serve": {
        const app = createApp(service);
        const portFlag = args.flags.port;
        const preferred = typeof portFlag === "string" ? parseIntArg(portFlag, "port") : undefined;
        const { port } = await listen(app, preferred);
        console.log(`PE32+ 检查服务运行中: http://127.0.0.1:${port}`);
        console.log("数据目录:", dir);
        return await new Promise<number>((resolveFn) => {
          process.on("SIGINT", () => {
            app.close();
            store.close();
            resolveFn(0);
          });
        });
      }
      case "demo":
        return runDemo(service);
      default:
        printHelp();
        return args.command ? 1 : 0;
    }
  } catch (err) {
    if (err instanceof PeError) {
      console.error("解析/请求错误:", JSON.stringify(err.toJSON(), null, 2));
      return 2;
    }
    console.error((err as Error).message);
    return 1;
  } finally {
    if (args.command !== "serve") store.close();
  }
}

function runDemo(service: InspectorService): number {
  const fixDir = join(process.cwd(), "data", "fixtures");
  const normal = join(fixDir, "normal-name-import.exe");
  const bad = join(fixDir, "bad-import-rva.exe");
  console.log("== 演示 1：正常名称导入 ==");
  const ok = service.importFromBuffer("normal-name-import.exe", readFileSync(normal));
  console.log(`报告 id=${ok.report.id}`);
  printImports(ok.report.report.imports);

  console.log("\n== 演示 2：RVA 映射解释（取第一个名称 RVA） ==");
  const firstNameRva = ok.report.report.imports[0]?.functions[0]?.nameRva;
  if (typeof firstNameRva === "number") {
    const mapping = service.explainRva(ok.report.id, firstNameRva, 2);
    console.log(mapping.steps.join("\n"));
    console.log(`=> 文件偏移 0x${(mapping.fileOffset ?? 0).toString(16)}`);
  }

  console.log("\n== 演示 3：损坏的导入 RVA 定位 ==");
  try {
    service.importFromBuffer("bad-import-rva.exe", readFileSync(bad));
  } catch (err) {
    if (err instanceof PeError) {
      console.error("定位结果:", JSON.stringify(err.toJSON(), null, 2));
    }
  }
  console.log("\n（损坏文件未登记为成功报告；可用 `reports` 验证）");
  return 0;
}

function baseName(p: string): string {
  return p.split(/[\\/]/).filter(Boolean).pop() ?? p;
}

function printHelp(): void {
  console.log(`peinspect - 离线 PE32+ 导入表检查（仅后端）

用法:
  import <文件> [--name 名称]   只读解析并登记报告（重复内容幂等）
  reports                       列出已保存报告与解析器版本
  header <id>                   头部摘要
  sections <id>                 节表
  imports <id> [--json]         导入清单
  map <id> <rva> [length] [--json]  解释 RVA -> 文件偏移（退出码 2=不可映射）
  export <id> [输出文件]         导出完整 JSON 报告
  serve [--port 端口]           启动 HTTP API（默认自动选择空闲端口）
  demo                          生成并演示正常导入与损坏指针定位

通用选项:
  --data-dir <目录>             SQLite 与只读副本目录（默认 ./data）

整数支持十进制或 0x 十六进制。`);
}

main().then((code) => process.exitCode = code);
