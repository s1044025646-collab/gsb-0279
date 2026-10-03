import { test } from "node:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parsePe } from "../src/pe/parser.js";
import { PeError } from "../src/pe/errors.js";
import { ReportStore } from "../src/db.js";
import { InspectorService } from "../src/service.js";
import {
  normalNameImport,
  ordinalOnly,
  thunkFallback,
  noImports,
  zeroFillBss,
  overlappingSections,
  badPeOffset,
  truncatedNameString,
  badImportRva,
  missingTerminator,
  pe32NotSupported,
} from "./fixtures.js";

// node:test 的 assert 来自 node:assert/strict
import assertStrict from "node:assert/strict";

test("正常名称导入 + 序号导入", () => {
  const { report } = parsePe("a.exe", normalNameImport());
  assertStrict.equal(report.imports.length, 1);
  const dll = report.imports[0]!;
  assertStrict.equal(dll.name, "test.dll");
  assertStrict.equal(dll.usedThunk, "OriginalFirstThunk");
  assertStrict.equal(dll.functions.length, 2);
  const byName = dll.functions[0]!;
  assertStrict.equal(byName.name, "MyExport");
  assertStrict.equal(byName.hint, 1);
  assertStrict.equal(byName.ordinal, null);
  // hint/name 位于磁盘偏移 0x4e0，RVA 0x20e0（RVA != 文件偏移）
  assertStrict.equal(byName.sourceFileOffset, 0x4e0);
  assertStrict.equal(byName.nameRva, 0x20e0);
  const byOrd = dll.functions[1]!;
  assertStrict.equal(byOrd.name, null);
  assertStrict.equal(byOrd.ordinal, 7);
});

test("RVA 与文件偏移不同且可解释", () => {
  const { mapper } = parsePe("a.exe", normalNameImport());
  const m = mapper.explain(0x20e0, 2);
  assertStrict.equal(m.mappable, true);
  assertStrict.equal(m.fileOffset, 0x4e0);
  assertStrict.equal(m.region, "section");
  assertStrict.equal(m.sectionName, ".rdata");
});

test("头部区 RVA 恒等映射", () => {
  const { mapper } = parsePe("a.exe", normalNameImport());
  const m = mapper.explain(0x3c, 4);
  assertStrict.equal(m.mappable, true);
  assertStrict.equal(m.fileOffset, 0x3c);
  assertStrict.equal(m.region, "header");
});

test("纯序号导入", () => {
  const { report } = parsePe("o.exe", ordinalOnly());
  const fn = report.imports[0]!.functions[0]!;
  assertStrict.equal(fn.ordinal, 42);
  assertStrict.equal(fn.name, null);
});

test("OriginalFirstThunk 缺失时回退 FirstThunk", () => {
  const { report } = parsePe("f.exe", thunkFallback());
  const dll = report.imports[0]!;
  assertStrict.equal(dll.usedThunk, "FirstThunk");
  assertStrict.equal(dll.functions[0]!.name, "FallbackFunc");
  assertStrict.equal(dll.functions[0]!.viaFallback, true);
  assertStrict.ok(report.warnings.some((w) => w.code === "THUNK_FALLBACK"));
});

test("无导入表是合法状态", () => {
  const { report } = parsePe("n.exe", noImports());
  assertStrict.equal(report.hasImportDirectory, false);
  assertStrict.equal(report.imports.length, 0);
});

test("虚拟零填充（.bss 无原始字节）不可作为内容读取", () => {
  const { mapper } = parsePe("b.exe", zeroFillBss());
  const m = mapper.explain(0x3100, 1);
  assertStrict.equal(m.mappable, false);
  assertStrict.equal(m.region, "zero-fill");
  assertStrict.throws(() => mapper.resolve(0x3100, 1), (e: unknown) => (e as PeError).code === "VIRTUAL_ZERO_FILL");
});

test("重叠节被报告且歧义 RVA 拒绝映射", () => {
  const { report, mapper } = parsePe("ov.exe", overlappingSections());
  assertStrict.ok(report.warnings.some((w) => w.code === "OVERLAPPING_SECTIONS"));
  const m = mapper.explain(0x2150, 1);
  assertStrict.equal(m.mappable, false);
  assertStrict.match(m.reason ?? "", /多重映射/);
});

test("坏 PE 头位置", () => {
  assertStrict.throws(() => parsePe("bad.exe", badPeOffset()), (e: unknown) => (e as PeError).code === "BAD_PE_OFFSET");
});

test("截断的零终止函数名", () => {
  assertStrict.throws(() => parsePe("t.exe", truncatedNameString()), (e: unknown) => (e as PeError).code === "TRUNCATED_READ");
});

test("坏导入目录 RVA", () => {
  try {
    parsePe("bi.exe", badImportRva());
    assertStrict.fail("应当抛出");
  } catch (e) {
    const pe = e as PeError;
    assertStrict.ok(pe.code === "BAD_RVA" || pe.code === "TRUNCATED_READ");
    assertStrict.equal(pe.rva, 0x9000);
  }
});

test("缺少终止描述符", () => {
  assertStrict.throws(
    () => parsePe("mt.exe", missingTerminator()),
    (e: unknown) => ["IMPORT_MISSING_TERMINATOR", "TRUNCATED_READ", "BAD_RVA"].includes((e as PeError).code),
  );
});

test("32 位 PE 明确不支持", () => {
  assertStrict.throws(() => parsePe("p32.exe", pe32NotSupported()), (e: unknown) =>
    ["NOT_PE32_PLUS", "UNSUPPORTED_MACHINE"].includes((e as PeError).code),
  );
});

test("导入 hint/name 的每个字节区间都必须在文件内", () => {
  // 独立校验：遍历正常文件全部导入引用，确认映射区间严格位于文件尺寸内
  const data = normalNameImport();
  const { report, mapper } = parsePe("a.exe", data);
  for (const dll of report.imports) {
    const dn = mapper.explain(dll.nameRva, 1);
    assertStrict.ok(dn.mappable && dn.fileOffset !== null && dn.fileOffset < data.length);
    for (const fn of dll.functions) {
      if (fn.nameRva !== null) {
        const nm = mapper.explain(fn.nameRva, 2);
        assertStrict.ok(nm.mappable);
        assertStrict.ok((nm.fileOffset ?? -1) + 2 <= data.length);
      }
      const tm = mapper.explain(fn.thunkRva, 8);
      assertStrict.ok(tm.mappable);
      assertStrict.ok((tm.fileOffset ?? -1) + 8 <= data.length);
    }
  }
});

test("重复导入幂等且失败不登记；重启后可查旧报告", () => {
  const dir = mkdtempSync(join(tmpdir(), "peinspect-"));
  const store1 = new ReportStore(dir);
  const svc1 = new InspectorService(store1);
  const first = svc1.importFromBuffer("dup.exe", normalNameImport());
  assertStrict.equal(first.duplicated, false);
  const second = svc1.importFromBuffer("dup-other-name.exe", normalNameImport());
  assertStrict.equal(second.duplicated, true);
  assertStrict.equal(second.report.id, first.report.id);
  assertStrict.throws(() => svc1.importFromBuffer("bad.exe", badImportRva()));
  assertStrict.equal(svc1.list().length, 1);
  store1.close();

  // 模拟服务重启：重新打开同一数据目录
  const store2 = new ReportStore(dir);
  const svc2 = new InspectorService(store2);
  const list = svc2.list();
  assertStrict.equal(list.length, 1);
  const reloaded = svc2.get(first.report.id);
  assertStrict.equal(reloaded.report.imports[0]!.name, "test.dll");
  assertStrict.equal(store2.parserVersion(), reloaded.parser_version);
  store2.close();
});
