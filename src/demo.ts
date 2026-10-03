/**
 * Demo: generate synthetic PE32+ samples (valid + corrupt), import them,
 * print the import list, explain an RVA, and locate a corrupt pointer.
 */
import fs from "node:fs";
import path from "node:path";
import { buildSamplePe } from "./samplePe.js";
import { Store } from "./db.js";
import { PeService } from "./service.js";

const dataDir = path.join(process.cwd(), "data");
const samplesDir = path.join(dataDir, "samples");
fs.mkdirSync(samplesDir, { recursive: true });

const good = buildSamplePe({
  imports: [
    { dll: "KERNEL32.dll", names: [[0, "ExitProcess"], [4, "CreateFileW"]], ordinals: [12] },
    { dll: "USER32.dll", names: [[0, "MessageBoxW"]], forceFallback: true },
  ],
});
const corrupt = buildSamplePe({ imports: [{ dll: "KERNEL32.dll", names: [[0, "ExitProcess"]] }] });
// Corrupt: point the DLL-name RVA of descriptor #0 into unmapped space.
corrupt.buf.writeUInt32LE(0x00dead00, corrupt.layout.descriptorFileOffset + 12);

const goodPath = path.join(samplesDir, "good.exe");
const corruptPath = path.join(samplesDir, "corrupt.exe");
fs.writeFileSync(goodPath, good.buf);
fs.writeFileSync(corruptPath, corrupt.buf);

const service = new PeService(new Store(dataDir));

console.log("=== import good.exe ===");
const r1 = service.importFile(goodPath, true);
console.log(`fileId=${r1.fileId} reportId=${r1.reportId} status=${r1.status} sha256=${r1.sha256.slice(0, 16)}...`);
for (const dll of service.imports(r1.fileId)) {
  console.log(`DLL ${dll.name} (descriptor@0x${dll.descriptorFileOffset.toString(16)}, fallback=${dll.usedFallback})`);
  for (const f of dll.functions) {
    const what = f.kind === "name" ? `name=${f.name} hint=${f.hint}` : `ordinal=${f.ordinal}`;
    console.log(`  ${what}  thunk@file 0x${f.thunkFileOffset.toString(16)} (RVA ${f.thunkRva}) via ${f.thunkSource}`);
  }
}

console.log("\n=== explain RVA 0x1000 (good.exe) ===");
console.log(JSON.stringify(service.explainRva(r1.fileId, 0x1000), null, 2));

console.log("\n=== import corrupt.exe (bad DLL-name RVA) ===");
const r2 = service.importFile(corruptPath, true);
console.log(`status=${r2.status} code=${r2.error?.code}`);
console.log(`reason: ${r2.error?.message}`);
console.log(`file offset of failing pointer: 0x${(r2.error?.fileOffset ?? 0).toString(16)}`);

console.log("\n=== persisted reports (survive restart) ===");
for (const r of service.store.listReports()) {
  console.log(`report #${r.id} file=${r.file_name} status=${r.status} parser=${r.parser_version} at=${r.created_at}`);
}
service.store.close();
