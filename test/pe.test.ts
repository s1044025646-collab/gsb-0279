import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parsePe, mapperFor } from "../src/pe/parser.js";
import { PeError } from "../src/pe/errors.js";
import { buildSamplePe } from "../src/samplePe.js";
import { Store } from "../src/db.js";
import { PeService } from "../src/service.js";

function expectPeError(code: string, fn: () => void): PeError {
  try {
    fn();
  } catch (e: any) {
    assert.ok(e instanceof PeError, `expected PeError, got ${e}`);
    assert.equal(e.code, code, `expected ${code}, got ${e.code}: ${e.message}`);
    return e as PeError;
  }
  assert.fail(`expected PeError ${code}, but no error was thrown`);
}

test("name imports: DLL, hint, name and exact file offsets", () => {
  const { buf, layout } = buildSamplePe({
    imports: [{ dll: "KERNEL32.dll", names: [[0, "ExitProcess"], [1, "GetLastError"]] }],
  });
  const r = parsePe(buf);
  assert.equal(r.imports.length, 1);
  const dll = r.imports[0];
  assert.equal(dll.name, "KERNEL32.dll");
  assert.equal(dll.usedFallback, false);
  assert.equal(dll.descriptorFileOffset, layout.descriptorFileOffset);
  assert.equal(dll.nameFileOffset, layout.dllNameFileOffset);
  assert.deepEqual(
    dll.functions.map((f) => [f.kind, f.name, f.hint]),
    [
      ["name", "ExitProcess", 0],
      ["name", "GetLastError", 1],
    ],
  );
  assert.equal(dll.functions[0].thunkFileOffset, layout.thunkFileOffset);
  assert.equal(dll.functions[0].nameFileOffset, layout.firstFuncNameFileOffset);
  assert.equal(dll.functions[0].thunkSource, "OriginalFirstThunk");
});

test("ordinal imports keep bit 63 via BigInt (no 32-bit truncation)", () => {
  const { buf } = buildSamplePe({ imports: [{ dll: "WS2_32.dll", ordinals: [23, 115] }] });
  const r = parsePe(buf);
  const fns = r.imports[0].functions;
  assert.deepEqual(
    fns.map((f) => [f.kind, f.ordinal]),
    [
      ["ordinal", 23],
      ["ordinal", 115],
    ],
  );
  assert.equal(fns[0].thunkValue, "0x8000000000000017");
});

test("mixed name+ordinal and FirstThunk fallback when OriginalFirstThunk is 0", () => {
  const { buf } = buildSamplePe({
    imports: [{ dll: "USER32.dll", names: [[0, "MessageBoxA"]], ordinals: [7], forceFallback: true }],
  });
  const r = parsePe(buf);
  const dll = r.imports[0];
  assert.equal(dll.usedFallback, true);
  assert.equal(dll.originalFirstThunk, "0x0");
  assert.equal(dll.functions[0].thunkSource, "FirstThunk(fallback)");
  assert.equal(dll.functions[0].name, "MessageBoxA");
  assert.equal(dll.functions[1].kind, "ordinal");
});

test("no import directory is a valid state", () => {
  const { buf } = buildSamplePe({ noImports: true });
  const r = parsePe(buf);
  assert.equal(r.importDirectory, null);
  assert.deepEqual(r.imports, []);
  assert.ok(r.notes.some((n) => n.includes("No import directory")));
});

test("RVA and file offset differ; mapping steps are explained", () => {
  const { buf, layout } = buildSamplePe({ imports: [{ dll: "A.dll", names: [[0, "f"]] }] });
  const r = parsePe(buf);
  const mapper = mapperFor(r);
  assert.equal(mapper.map(0x40).fileOffset, 0x40);
  const m = mapper.map(layout.rdataVirtualAddress + 0x10);
  assert.equal(m.fileOffset, layout.rdataPointerToRawData + 0x10);
  assert.notEqual(m.fileOffset, layout.rdataVirtualAddress + 0x10);
  assert.equal(m.step.sectionName, ".rdata");
  assert.equal(m.step.delta, "0x10");
  const bad = mapper.explain(0x700000);
  assert.equal(bad.ok, false);
  assert.equal(bad.error!.code, "RVA_UNMAPPED");
});

test("virtual zero-fill region cannot be read as file bytes", () => {
  const { buf } = buildSamplePe({
    noImports: true,
    extraSections: [{ name: ".bss", virtualSize: 0x600, sizeOfRawData: 0x200 }],
  });
  const r = parsePe(buf);
  const mapper = mapperFor(r);
  const sec = r.sections[1];
  mapper.map(sec.virtualAddress + 0x100);
  const e = expectPeError("RVA_ZERO_FILL", () => mapper.map(sec.virtualAddress + 0x300));
  assert.ok(e.message.includes(".bss"));
});

test("overlapping sections are reported as ambiguous", () => {
  const { buf } = buildSamplePe({
    noImports: true,
    extraSections: [{ name: ".dup", virtualSize: 0x100, sizeOfRawData: 0x200, virtualAddress: 0x1000 }],
  });
  const r = parsePe(buf);
  const mapper = mapperFor(r);
  const e = expectPeError("RVA_AMBIGUOUS", () => mapper.map(0x1010));
  assert.ok(e.message.includes(".dup") && e.message.includes(".rdata"));
});

test("bad e_lfanew and bad signatures are rejected with offsets", () => {
  const bad1 = buildSamplePe({ badELfanew: 0xffff00 }).buf;
  const e1 = expectPeError("BAD_ELFANEW", () => parsePe(bad1));
  assert.equal(e1.fileOffset, 0x3c);

  const bad2 = buildSamplePe({}).buf;
  bad2.writeUInt32LE(0xdeadbeef, 0x80);
  const e2 = expectPeError("BAD_PE_SIGNATURE", () => parsePe(bad2));
  assert.equal(e2.fileOffset, 0x80);

  const bad3 = buildSamplePe({}).buf;
  bad3.writeUInt16LE(0x14c, 0x80 + 4);
  expectPeError("UNSUPPORTED_MACHINE", () => parsePe(bad3));

  const bad4 = buildSamplePe({}).buf;
  bad4.writeUInt16LE(0x10b, 0x80 + 24);
  expectPeError("UNSUPPORTED_OPTIONAL_MAGIC", () => parsePe(bad4));
});

test("truncated file and unterminated string report concrete offsets", () => {
  const good = buildSamplePe({ imports: [{ dll: "KERNEL32.dll", names: [[0, "ExitProcess"]] }] });
  const cut = good.buf.subarray(0, good.layout.descriptorFileOffset + 5);
  const e1 = expectPeError("TRUNCATED", () => parsePe(Buffer.from(cut)));
  assert.equal(typeof e1.fileOffset, "number");

  const unterm = buildSamplePe({
    imports: [{ dll: "KERNEL32.dll", names: [[0, "ExitProcess"]] }],
    unterminatedName: true,
  });
  const e2 = expectPeError("UNTERMINATED_STRING", () => parsePe(unterm.buf));
  assert.equal(e2.fileOffset, unterm.layout.firstFuncNameFileOffset + 2);
});

test("corrupt thunk pointer to unmapped RVA is rejected with a concrete offset", () => {
  const { buf, layout } = buildSamplePe({ imports: [{ dll: "X.dll", names: [[0, "g"]] }] });
  buf.writeBigUInt64LE(0x00dead00n, layout.thunkFileOffset);
  const e = expectPeError("RVA_UNMAPPED", () => parsePe(buf));
  assert.equal(typeof e.fileOffset, "number");
});

test("every byte range of import records lies inside the file", () => {
  const { buf } = buildSamplePe({
    imports: [
      { dll: "KERNEL32.dll", names: [[0, "ExitProcess"], [3, "CreateFileW"]], ordinals: [12] },
      { dll: "USER32.dll", names: [[0, "MessageBoxW"]], forceFallback: true },
    ],
  });
  const r = parsePe(buf);
  const inRange = (off: number, len: number) => {
    assert.ok(Number.isInteger(off) && off >= 0 && off + len <= buf.length, `range ${off}+${len} outside ${buf.length}`);
  };
  for (const dll of r.imports) {
    inRange(dll.descriptorFileOffset, 20);
    inRange(dll.nameFileOffset, dll.name.length + 1);
    assert.equal(buf.toString("ascii", dll.nameFileOffset, dll.nameFileOffset + dll.name.length), dll.name);
    for (const f of dll.functions) {
      inRange(f.thunkFileOffset, 8);
      assert.equal("0x" + buf.readBigUInt64LE(f.thunkFileOffset).toString(16), f.thunkValue);
      if (f.kind === "name") {
        inRange(f.nameFileOffset!, 2 + f.name!.length + 1);
        assert.equal(buf.readUInt16LE(f.nameFileOffset!), f.hint);
        assert.equal(buf.toString("ascii", f.nameFileOffset! + 2, f.nameFileOffset! + 2 + f.name!.length), f.name);
      }
    }
  }
});

test("service: import, persist, deterministic re-import, restart persistence", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pe-inspect-"));
  const sample = buildSamplePe({ imports: [{ dll: "KERNEL32.dll", names: [[0, "ExitProcess"]] }] });
  const samplePath = path.join(dir, "sample.exe");
  fs.writeFileSync(samplePath, sample.buf);

  const svc1 = new PeService(new Store(path.join(dir, "data")));
  const r1 = svc1.importFile(samplePath);
  assert.equal(r1.status, "ok");
  assert.equal(r1.reused, false);
  const imports = svc1.imports(r1.fileId);
  assert.equal(imports[0].functions[0].name, "ExitProcess");
  const rva = svc1.explainRva(r1.fileId, sample.layout.rdataVirtualAddress);
  assert.equal(rva.ok, true);
  assert.equal(rva.step.fileOffset, sample.layout.rdataPointerToRawData);
  svc1.store.close();

  const svc2 = new PeService(new Store(path.join(dir, "data")));
  const r2 = svc2.importFile(samplePath);
  assert.equal(r2.reused, true);
  assert.equal(r2.fileId, r1.fileId);
  assert.equal(r2.reportId, r1.reportId);
  svc2.store.close();

  const svc3 = new PeService(new Store(path.join(dir, "data")));
  const exp = svc3.exportReport(r1.reportId);
  assert.equal(exp.status, "ok");
  assert.equal(exp.report.imports[0].name, "KERNEL32.dll");
  svc3.store.close();
});

test("service: failed parse is recorded as failed, never as success", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pe-inspect-"));
  const bad = buildSamplePe({ badELfanew: 0x7fff00 });
  const p = path.join(dir, "bad.exe");
  fs.writeFileSync(p, bad.buf);
  const svc = new PeService(new Store(path.join(dir, "data")));
  const r = svc.importFile(p);
  assert.equal(r.status, "failed");
  assert.equal(r.error!.code, "BAD_ELFANEW");
  const exp = svc.exportReport(r.reportId);
  assert.equal(exp.status, "failed");
  assert.equal(exp.report, null);
  assert.throws(() => svc.imports(r.fileId), /failed/);
  svc.store.close();
});
