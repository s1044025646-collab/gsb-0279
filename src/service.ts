import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { Store } from "./db.js";
import { parsePe, mapperFor, PeReport } from "./pe/parser.js";
import { PeError } from "./pe/errors.js";
import { PARSER_VERSION } from "./limits.js";

export interface ImportResult {
  fileId: number;
  reportId: number;
  status: "ok" | "failed";
  reused: boolean;
  sha256: string;
  error?: { code: string; message: string; fileOffset?: number; rva?: string };
}

export class PeService {
  constructor(readonly store: Store) {}

  /**
   * Import a PE file: hash it, keep a read-only copy under the data dir,
   * parse it and persist the report. Re-importing identical content is
   * deterministic: the existing file row and its latest report are returned
   * without re-parsing (pass force=true to re-parse).
   */
  importFile(sourcePath: string, force = false): ImportResult {
    if (!fs.existsSync(sourcePath)) {
      throw new PeError("VALIDATION", `Input file not found: ${sourcePath}`);
    }
    const buf = fs.readFileSync(sourcePath);
    const sha256 = crypto.createHash("sha256").update(buf).digest("hex");

    const existing = this.store.findFileByHash(sha256);
    if (existing && !force) {
      const rep = this.store.latestReportForFile(existing.id);
      return {
        fileId: existing.id,
        reportId: rep?.id ?? 0,
        status: (rep?.status as "ok" | "failed") ?? "failed",
        reused: true,
        sha256,
        error: rep?.error_code ? { code: rep.error_code, message: rep.error_message ?? "" } : undefined,
      };
    }

    let fileId: number;
    if (existing) {
      fileId = existing.id;
    } else {
      const storedName = `${sha256.slice(0, 16)}_${path.basename(sourcePath)}`;
      const storedPath = path.join(this.store.filesDir, storedName);
      fs.copyFileSync(sourcePath, storedPath);
      fs.chmodSync(storedPath, 0o444); // read-only project copy
      fileId = this.store.insertFile({ sha256, name: path.basename(sourcePath), size: buf.length, storedPath });
    }

    try {
      const report = parsePe(buf);
      const reportId = this.store.insertReport({
        fileId,
        parserVersion: PARSER_VERSION,
        status: "ok",
        reportJson: JSON.stringify(report),
      });
      return { fileId, reportId, status: "ok", reused: false, sha256 };
    } catch (e: any) {
      const pe: PeError = e instanceof PeError ? e : new PeError("VALIDATION", String(e?.message ?? e));
      const reportId = this.store.insertReport({
        fileId,
        parserVersion: PARSER_VERSION,
        status: "failed",
        errorCode: pe.code,
        errorOffset: pe.fileOffset ?? null,
        errorMessage: pe.message,
      });
      return {
        fileId,
        reportId,
        status: "failed",
        reused: false,
        sha256,
        error: { code: pe.code, message: pe.message, fileOffset: pe.fileOffset, rva: pe.rva?.toString() },
      };
    }
  }

  private okReport(fileId: number): PeReport {
    const rep = this.store.latestReportForFile(fileId);
    if (!rep) throw new PeError("VALIDATION", `No report for file id ${fileId}`);
    if (rep.status !== "ok" || !rep.report_json) {
      throw new PeError("VALIDATION", `Latest report #${rep.id} for file ${fileId} failed: ${rep.error_code} ${rep.error_message}`);
    }
    return JSON.parse(rep.report_json) as PeReport;
  }

  summary(fileId: number) {
    const r = this.okReport(fileId);
    const f = this.store.getFile(fileId)!;
    return {
      file: { id: f.id, name: f.name, size: f.size, sha256: f.sha256, storedPath: f.stored_path },
      parserVersion: r.parserVersion,
      dosHeader: r.dosHeader,
      coff: r.coff,
      optionalHeader: r.optionalHeader,
      importDirectory: r.importDirectory,
      delayImportPresent: r.delayImportPresent,
      notes: r.notes,
    };
  }

  sections(fileId: number) {
    return this.okReport(fileId).sections;
  }

  imports(fileId: number) {
    return this.okReport(fileId).imports;
  }

  explainRva(fileId: number, rva: number) {
    const r = this.okReport(fileId);
    const mapper = mapperFor(r);
    const out = mapper.explain(rva) as any;
    out.imageBase = r.optionalHeader.imageBase;
    out.note =
      "RVA is relative to the image base. File offset = section.PointerToRawData + (RVA - section.VirtualAddress); " +
      "header RVAs map 1:1. Zero-fill regions have no disk bytes.";
    return out;
  }

  exportReport(reportId: number) {
    const rep = this.store.getReport(reportId);
    if (!rep) throw new PeError("VALIDATION", `No report with id ${reportId}`);
    return {
      id: rep.id,
      fileId: rep.file_id,
      fileName: rep.file_name,
      sha256: rep.sha256,
      parserVersion: rep.parser_version,
      status: rep.status,
      error: rep.error_code ? { code: rep.error_code, offset: rep.error_offset, message: rep.error_message } : null,
      createdAt: rep.created_at,
      report: rep.report_json ? JSON.parse(rep.report_json) : null,
    };
  }
}
