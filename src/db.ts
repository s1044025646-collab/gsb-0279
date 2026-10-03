import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { PARSER_VERSION } from "./pe/limits.js";
import type { ImportReport } from "./pe/types.js";

export interface StoredReport {
  id: number;
  sha256: string;
  file_name: string;
  file_size: number;
  parser_version: string;
  status: "ok";
  report: ImportReport;
  copy_path: string;
  created_at: string;
}

export class ReportStore {
  private db: DatabaseSync;
  private copyDir: string;

  constructor(dataDir: string) {
    mkdirSync(dataDir, { recursive: true });
    this.copyDir = join(dataDir, "files");
    mkdirSync(this.copyDir, { recursive: true });
    this.db = new DatabaseSync(join(dataDir, "reports.db"));
    this.db.exec("PRAGMA journal_mode=WAL;");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sha256 TEXT NOT NULL UNIQUE,
        file_name TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        parser_version TEXT NOT NULL,
        status TEXT NOT NULL,
        report_json TEXT NOT NULL,
        copy_path TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
    `);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `);
    this.db.prepare("INSERT OR IGNORE INTO meta(key,value) VALUES('parser_version',?)").run(PARSER_VERSION);
  }

  importFile(fileName: string, data: Buffer, report: ImportReport): { report: StoredReport; duplicated: boolean } {
    const sha256 = createHash("sha256").update(data).digest("hex");
    const existing = this.getBySha(sha256);
    if (existing) {
      return { report: existing, duplicated: true };
    }
    const copyPath = join(this.copyDir, `${sha256}.bin`);
    writeFileSync(copyPath, data, { flag: "wx" });
    const info = this.db
      .prepare(
        `INSERT INTO reports(sha256,file_name,file_size,parser_version,status,report_json,copy_path)
         VALUES(?,?,?,?,?,?,?)`,
      )
      .run(sha256, fileName, data.length, PARSER_VERSION, "ok", JSON.stringify(report), copyPath);
    const stored = this.getById(Number(info.lastInsertRowid));
    if (!stored) throw new Error("插入报告后无法读回");
    return { report: stored, duplicated: false };
  }

  private rowToReport(row: Record<string, unknown>): StoredReport {
    return {
      id: row.id as number,
      sha256: row.sha256 as string,
      file_name: row.file_name as string,
      file_size: row.file_size as number,
      parser_version: row.parser_version as string,
      status: "ok",
      report: JSON.parse(row.report_json as string) as ImportReport,
      copy_path: row.copy_path as string,
      created_at: row.created_at as string,
    };
  }

  getById(id: number): StoredReport | null {
    const row = this.db.prepare("SELECT * FROM reports WHERE id=?").get(id) as Record<string, unknown> | undefined;
    return row ? this.rowToReport(row) : null;
  }

  getBySha(sha256: string): StoredReport | null {
    const row = this.db.prepare("SELECT * FROM reports WHERE sha256=?").get(sha256) as Record<string, unknown> | undefined;
    return row ? this.rowToReport(row) : null;
  }

  list(): Array<Pick<StoredReport, "id" | "sha256" | "file_name" | "file_size" | "parser_version" | "created_at">> {
    const rows = this.db.prepare("SELECT id,sha256,file_name,file_size,parser_version,created_at FROM reports ORDER BY id").all() as Array<Record<string, unknown>>;
    return rows.map((row) => ({
      id: row.id as number,
      sha256: row.sha256 as string,
      file_name: row.file_name as string,
      file_size: row.file_size as number,
      parser_version: row.parser_version as string,
      created_at: row.created_at as string,
    }));
  }

  readCopy(stored: StoredReport): Buffer {
    return readFileSync(stored.copy_path);
  }

  parserVersion(): string {
    const row = this.db.prepare("SELECT value FROM meta WHERE key='parser_version'").get() as { value: string } | undefined;
    return row?.value ?? PARSER_VERSION;
  }

  close(): void {
    this.db.close();
  }
}
