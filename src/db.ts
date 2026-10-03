import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import fs from "node:fs";

export interface FileRow {
  id: number;
  sha256: string;
  name: string;
  size: number;
  stored_path: string;
  imported_at: string;
}

export interface ReportRow {
  id: number;
  file_id: number;
  parser_version: string;
  status: "ok" | "failed";
  error_code: string | null;
  error_offset: number | null;
  error_message: string | null;
  report_json: string | null;
  created_at: string;
}

export class Store {
  readonly db: DatabaseSync;
  readonly filesDir: string;

  constructor(readonly dataDir: string) {
    fs.mkdirSync(dataDir, { recursive: true });
    this.filesDir = path.join(dataDir, "files");
    fs.mkdirSync(this.filesDir, { recursive: true });
    this.db = new DatabaseSync(path.join(dataDir, "pe-inspect.db"));
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sha256 TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        size INTEGER NOT NULL,
        stored_path TEXT NOT NULL,
        imported_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER NOT NULL REFERENCES files(id),
        parser_version TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('ok','failed')),
        error_code TEXT,
        error_offset INTEGER,
        error_message TEXT,
        report_json TEXT,
        created_at TEXT NOT NULL
      );
    `);
  }

  findFileByHash(sha256: string): FileRow | undefined {
    return this.db.prepare("SELECT * FROM files WHERE sha256 = ?").get(sha256) as FileRow | undefined;
  }

  insertFile(f: { sha256: string; name: string; size: number; storedPath: string }): number {
    const r = this.db
      .prepare("INSERT INTO files (sha256, name, size, stored_path, imported_at) VALUES (?,?,?,?,?)")
      .run(f.sha256, f.name, f.size, f.storedPath, new Date().toISOString());
    return Number(r.lastInsertRowid);
  }

  insertReport(r: {
    fileId: number;
    parserVersion: string;
    status: "ok" | "failed";
    errorCode?: string | null;
    errorOffset?: number | null;
    errorMessage?: string | null;
    reportJson?: string | null;
  }): number {
    const res = this.db
      .prepare(
        `INSERT INTO reports (file_id, parser_version, status, error_code, error_offset, error_message, report_json, created_at)
         VALUES (?,?,?,?,?,?,?,?)`,
      )
      .run(
        r.fileId,
        r.parserVersion,
        r.status,
        r.errorCode ?? null,
        r.errorOffset ?? null,
        r.errorMessage ?? null,
        r.reportJson ?? null,
        new Date().toISOString(),
      );
    return Number(res.lastInsertRowid);
  }

  latestReportForFile(fileId: number): ReportRow | undefined {
    return this.db.prepare("SELECT * FROM reports WHERE file_id = ? ORDER BY id DESC LIMIT 1").get(fileId) as
      | ReportRow
      | undefined;
  }

  getFile(id: number): FileRow | undefined {
    return this.db.prepare("SELECT * FROM files WHERE id = ?").get(id) as FileRow | undefined;
  }

  listFiles(): (FileRow & { latest_report_id: number | null; latest_status: string | null })[] {
    return this.db
      .prepare(
        `SELECT f.*, (SELECT id FROM reports r WHERE r.file_id = f.id ORDER BY id DESC LIMIT 1) AS latest_report_id,
                (SELECT status FROM reports r WHERE r.file_id = f.id ORDER BY id DESC LIMIT 1) AS latest_status
         FROM files f ORDER BY f.id`,
      )
      .all() as any[];
  }

  getReport(id: number): (ReportRow & { file_name?: string; sha256?: string }) | undefined {
    return this.db
      .prepare(
        `SELECT r.*, f.name AS file_name, f.sha256 AS sha256 FROM reports r JOIN files f ON f.id = r.file_id WHERE r.id = ?`,
      )
      .get(id) as any;
  }

  listReports(): any[] {
    return this.db
      .prepare(
        `SELECT r.id, r.file_id, f.name AS file_name, r.status, r.error_code, r.parser_version, r.created_at
         FROM reports r JOIN files f ON f.id = r.file_id ORDER BY r.id`,
      )
      .all() as any[];
  }

  close() {
    this.db.close();
  }
}
