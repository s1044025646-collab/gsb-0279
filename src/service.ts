import { readFileSync } from "node:fs";
import { RvaMapper } from "./pe/mapper.js";
import { parsePe } from "./pe/parser.js";
import { PeError } from "./pe/errors.js";
import { ReportStore, StoredReport } from "./db.js";

export class InspectorService {
  constructor(private store: ReportStore) {}

  importFromPath(absPath: string, fileName?: string) {
    const data = readFileSync(absPath);
    const { report } = parsePe(fileName ?? baseName(absPath), data);
    return this.store.importFile(fileName ?? baseName(absPath), data, report);
  }

  importFromBuffer(fileName: string, data: Buffer) {
    const { report } = parsePe(fileName, data);
    return this.store.importFile(fileName, data, report);
  }

  list() {
    return this.store.list();
  }

 get(id: number): StoredReport {
    const s = this.store.getById(id);
    if (!s) throw new PeError("INTERNAL", `报告 id=${id} 不存在`, { details: { id } });
    return s;
  }

  mapperFor(stored: StoredReport): RvaMapper {
    const data = this.store.readCopy(stored);
    return new RvaMapper(stored.report.sections, stored.report.header.sizeOfHeaders, data.length);
  }

  explainRva(id: number, rva: number, length: number) {
    const stored = this.get(id);
    const mapper = this.mapperFor(stored);
    return { reportId: id, ...mapper.explain(rva, length) };
  }
}

function baseName(p: string): string {
  return p.split(/[\\/]/).filter(Boolean).pop() ?? p;
}
