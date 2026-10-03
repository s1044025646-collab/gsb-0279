import { createHash } from "node:crypto";
import { BlobReader } from "./reader.js";
import { RvaMapper } from "./mapper.js";
import { PeError } from "./errors.js";
import { LIMITS, PARSER_VERSION } from "./limits.js";
import type {
  HeaderSummary,
  ImportedDll,
  ImportedFunction,
  ParseWarning,
  SectionInfo,
} from "./types.js";

const IMAGE_FILE_MACHINE_AMD64 = 0x8664;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;
const IMAGE_ORDINAL_FLAG64 = 0x8000000000000000n;
const IMPORT_DIR_INDEX = 1;
const DELAY_DIR_INDEX = 13;

const MACHINE_NAMES: Record<number, string> = {
  0x14c: "i386 (32位，不支持)",
  0x8664: "AMD64 / x86_64",
  0xaa64: "ARM64",
};

function decodeSectionName(raw: Buffer): string {
  const nul = raw.indexOf(0);
  const end = nul === -1 ? raw.length : nul;
  return raw.subarray(0, end).toString("ascii");
}

export interface ParseResult {
  report: Omit<import("./types.js").ImportReport, never>;
  mapper: RvaMapper;
}

export function parsePe(fileName: string, data: Buffer): ParseResult {
  if (data.length === 0) throw new PeError("FILE_EMPTY", "文件为空");
  if (data.length > LIMITS.maxFileSize) {
    throw new PeError("FILE_TOO_LARGE", `文件大小 ${data.length} 超过上限 ${LIMITS.maxFileSize}`);
  }

  const r = new BlobReader(data);
  const warnings: ParseWarning[] = [];
  const unsupported: string[] = [];

  if (r.u16(0) !== 0x5a4d) {
    throw new PeError("BAD_DOS_SIGNATURE", "缺少 DOS 标记 'MZ'", { fileOffset: 0 });
  }
  const peOffset = r.u32(0x3c);
  if (peOffset <= 0 || peOffset >= data.length || peOffset + 24 > data.length) {
    throw new PeError("BAD_PE_OFFSET", `e_lfanew=0x${peOffset.toString(16)} 无法容纳 PE 头`, {
      fileOffset: 0x3c,
      details: { e_lfanew: peOffset },
    });
  }
  if (r.u32(peOffset) !== 0x00004550) {
    throw new PeError("BAD_PE_SIGNATURE", "缺少 PE\\0\\0 标记", { fileOffset: peOffset });
  }

  const coff = peOffset + 4;
  const machine = r.u16(coff + 0);
  const numberOfSections = r.u16(coff + 2);
  const timeDateStamp = r.u32(coff + 4);
  const characteristics = r.u16(coff + 18);

  if (machine !== IMAGE_FILE_MACHINE_AMD64) {
    throw new PeError("UNSUPPORTED_MACHINE", `Machine=0x${machine.toString(16)}（${MACHINE_NAMES[machine] ?? "未知"}），本服务仅支持 AMD64 PE32+`, {
      fileOffset: coff,
    });
  }
  if (numberOfSections > LIMITS.maxSections) {
    throw new PeError("TOO_MANY_SECTIONS", `节数量 ${numberOfSections} 超过上限 ${LIMITS.maxSections}`, { fileOffset: coff + 2 });
  }

  const opt = coff + 20;
  const magic = r.u16(opt);
  if (magic !== IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    if (magic === 0x10b) {
      throw new PeError("NOT_PE32_PLUS", "可选头 Magic=0x10b 为 PE32（32位），不在支持范围", { fileOffset: opt });
    }
    throw new PeError("UNSUPPORTED_OPTIONAL_MAGIC", `可选头 Magic=0x${magic.toString(16)} 无法识别`, { fileOffset: opt });
  }

  const addressOfEntryPoint = r.u32(opt + 16);
  const imageBase = r.u64(opt + 24);
  const sizeOfImage = r.u32(opt + 56);
  const sizeOfHeaders = r.u32(opt + 60);
  const subsystem = r.u16(opt + 68);
  const numRvaAndSizes = r.u32(opt + 108);
  const dirBase = opt + 112;

  const dataDir = (index: number): { rva: number; size: number } => {
    if (index >= numRvaAndSizes) return { rva: 0, size: 0 };
    const off = dirBase + index * 8;
    if (off + 8 > data.length) {
      throw new PeError("TRUNCATED_HEADER", "数据目录超出文件范围", { fileOffset: off });
    }
    return { rva: r.u32(off), size: r.u32(off + 4) };
  };

  const importDir = dataDir(IMPORT_DIR_INDEX);
  const delayDir = dataDir(DELAY_DIR_INDEX);
  if (delayDir.rva !== 0 || delayDir.size !== 0) {
    unsupported.push("DELAY_IMPORT");
    warnings.push({ code: "UNSUPPORTED_DELAY_IMPORT", message: "存在延迟导入目录，本服务不解析延迟导入" });
  }

  const sectionStart = opt + 240;
  if (numberOfSections > 0 && sectionStart + numberOfSections * 40 > data.length) {
    throw new PeError("TRUNCATED_SECTION_TABLE", "节表超出文件范围", { fileOffset: sectionStart });
  }

  const sections: SectionInfo[] = [];
  for (let i = 0; i < numberOfSections; i++) {
    const so = sectionStart + i * 40;
    const name = decodeSectionName(r.bytes(so, 8));
    const virtualSize = r.u32(so + 8);
    const virtualAddress = r.u32(so + 12);
    const rawSize = r.u32(so + 16);
    const rawOffset = r.u32(so + 20);
    const sectionCharacteristics = r.u32(so + 36);
    if (rawSize > 0 && (rawOffset >= data.length || rawOffset + rawSize > data.length)) {
      throw new PeError("INVALID_SECTION", `节 ${name} 的原始数据 [0x${rawOffset.toString(16)}, +0x${rawSize.toString(16)}) 超出文件`, {
        fileOffset: rawOffset,
      });
    }
    sections.push({ name, virtualAddress, virtualSize, rawSize, rawOffset, characteristics: sectionCharacteristics });
  }

  const mapper = new RvaMapper(sections, sizeOfHeaders, data.length);
  if (mapper.overlapSections.length > 0) {
    warnings.push({
      code: "OVERLAPPING_SECTIONS",
      message: `检测到重叠节: ${mapper.overlapSections.map((p) => p.join("/")).join("; ")}（多重映射将被拒绝）`,
    });
  }

  const header: HeaderSummary = {
    machine,
    machineName: MACHINE_NAMES[machine] ?? "未知",
    numberOfSections,
    timeDateStamp,
    characteristics,
    imageBase: "0x" + imageBase.toString(16),
    addressOfEntryPoint,
    sizeOfImage,
    sizeOfHeaders,
    subsystem,
    magic,
    peOffset,
    isPe32Plus: true,
  };

  const imports = importDir.rva !== 0 ? parseImports(r, mapper, importDir.rva, importDir.size, warnings, unsupported) : [];

  const sha256 = createHash("sha256").update(data).digest("hex");
  return {
    report: {
      parserVersion: PARSER_VERSION,
      sha256,
      fileName,
      fileSize: data.length,
      header,
      sections,
      imports,
      hasImportDirectory: importDir.rva !== 0,
      warnings,
      unsupported,
    },
    mapper,
  };
}

function parseImports(
  r: BlobReader,
  mapper: RvaMapper,
  dirRva: number,
  dirSize: number,
  warnings: ParseWarning[],
  unsupported: string[],
): ImportedDll[] {
  const descSize = 20;
  const dlls: ImportedDll[] = [];
  let index = 0;
  let sawTerminator = false;

  for (;;) {
    if (index >= LIMITS.maxDescriptors) {
      throw new PeError("TOO_MANY_DESCRIPTORS", `导入描述符数量超过上限 ${LIMITS.maxDescriptors}`, { rva: dirRva });
    }
    const entryRva = dirRva + index * descSize;
    let entryOff: number;
    try {
      entryOff = mapper.resolve(entryRva, descSize);
    } catch (err) {
      if (index > 0 && err instanceof PeError && (err.code === "BAD_RVA" || err.code === "TRUNCATED_READ" || err.code === "VIRTUAL_ZERO_FILL")) {
        throw new PeError("IMPORT_MISSING_TERMINATOR", `导入目录在第 ${index} 个描述符处越界，且此前未遇到全零终止项`, {
          rva: entryRva,
        });
      }
      throw err;
    }
    const originalFirstThunk = r.u32(entryOff + 0);
    const timeDateStamp = r.u32(entryOff + 4);
    const forwarderChain = r.u32(entryOff + 8);
    const nameRva = r.u32(entryOff + 12);
    const firstThunk = r.u32(entryOff + 16);

    if (originalFirstThunk === 0 && nameRva === 0 && firstThunk === 0) {
      sawTerminator = true;
      break;
    }

    if (nameRva === 0) {
      throw new PeError("BAD_IMPORT_DIRECTORY", `第 ${index} 个导入描述符 Name RVA 为 0`, {
        fileOffset: entryOff + 12,
        rva: entryRva,
      });
    }

    const nameOff = mapper.resolve(nameRva, 1);
    const { text: dllName } = r.readCString(nameOff, LIMITS.maxDllNameLength, "NAME_TOO_LONG");

    const useOriginal = originalFirstThunk !== 0;
    const usedThunkRva = useOriginal ? originalFirstThunk : firstThunk;
    if (!useOriginal) {
      warnings.push({
        code: "THUNK_FALLBACK",
        message: `DLL ${dllName} 的 OriginalFirstThunk 为 0，回退使用 FirstThunk`,
        rva: entryRva,
      });
    }
    if (usedThunkRva === 0) {
      throw new PeError("BAD_IMPORT_DIRECTORY", `DLL ${dllName} 没有可用的 thunk 表`, { rva: entryRva });
    }
    if (timeDateStamp !== 0) {
      unsupported.push("BOUND_IMPORT");
      warnings.push({ code: "UNSUPPORTED_BOUND_IMPORT", message: `DLL ${dllName} 的 TimeDateStamp 非零，疑似绑定导入，忽略绑定信息` });
    }
    void forwarderChain;

    const functions = parseThunks(r, mapper, usedThunkRva, dllName, !useOriginal);
    dlls.push({
      name: dllName,
      nameRva,
      originalFirstThunk,
      firstThunk,
      usedThunk: useOriginal ? "OriginalFirstThunk" : "FirstThunk",
      timeDateStamp,
      functions,
    });
    index++;
  }

  if (!sawTerminator) {
    throw new PeError("IMPORT_MISSING_TERMINATOR", "导入目录缺少全零终止描述符", { rva: dirRva });
  }
  void dirSize;
  return dlls;
}

function parseThunks(
  r: BlobReader,
  mapper: RvaMapper,
  thunkRvaStart: number,
  dllName: string,
  viaFallback: boolean,
): ImportedFunction[] {
  const funcs: ImportedFunction[] = [];
  let i = 0;
  for (;;) {
    if (i >= LIMITS.maxThunks) {
      throw new PeError("TOO_MANY_THUNKS", `DLL ${dllName} 的 thunk 数量超过上限 ${LIMITS.maxThunks}`, { rva: thunkRvaStart });
    }
    const thunkRva = thunkRvaStart + i * 8;
    const off = mapper.resolve(thunkRva, 8);
    const value = r.u64(off);
    if (value === 0n) break;

    if ((value & IMAGE_ORDINAL_FLAG64) !== 0n) {
      const ordinal = Number(value & 0xffffn);
      funcs.push({
        ordinal,
        name: null,
        hint: null,
        thunkRva,
        nameRva: null,
        sourceFileOffset: off,
        viaFallback,
      });
    } else {
      const nameRva = Number(value & 0xffffffffn);
      const hintNameOff = mapper.resolve(nameRva, 2);
      const hint = r.u16(hintNameOff);
      const { text: funcName } = r.readCString(hintNameOff + 2, LIMITS.maxNameLength, "NAME_TOO_LONG");
      funcs.push({
        ordinal: null,
        name: funcName,
        hint,
        thunkRva,
        nameRva,
        sourceFileOffset: hintNameOff,
        viaFallback,
      });
    }
    i++;
  }
  return funcs;
}
