import { LIMITS, PARSER_VERSION } from "../limits.js";
import { err, PeError } from "./errors.js";
import { RvaMapper, SectionInfo } from "./rvaMap.js";

const IMAGE_FILE_MACHINE_AMD64 = 0x8664;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;
const ORDINAL_FLAG64 = 0x8000000000000000n;
const IMPORT_NAME_MASK64 = 0x7fffffffn; // low 31 bits, per PE spec
const DIR_ENTRY_IMPORT = 1;
const DIR_ENTRY_DELAY_IMPORT = 13;

export interface ImportedFunction {
  kind: "name" | "ordinal";
  /** Present for name imports. */
  name?: string;
  hint?: number;
  /** Present for ordinal imports. */
  ordinal?: number;
  /** Raw 64-bit thunk value, hex string. */
  thunkValue: string;
  /** File offset of the thunk entry we read. */
  thunkFileOffset: number;
  thunkRva: string;
  /** Which thunk array was used. */
  thunkSource: "OriginalFirstThunk" | "FirstThunk(fallback)";
  /** File offset of hint/name for name imports. */
  nameFileOffset?: number;
}

export interface ImportedDll {
  name: string;
  nameFileOffset: number;
  descriptorFileOffset: number;
  originalFirstThunk: string;
  firstThunk: string;
  usedFallback: boolean;
  functions: ImportedFunction[];
}

export interface PeReport {
  parserVersion: string;
  fileSize: number;
  dosHeader: { eMagic: string; eLfanew: number };
  coff: {
    machine: string;
    numberOfSections: number;
    timeDateStamp: number;
    characteristics: string;
  };
  optionalHeader: {
    magic: string;
    imageBase: string;
    sectionAlignment: number;
    fileAlignment: number;
    sizeOfImage: number;
    sizeOfHeaders: number;
    numberOfRvaAndSizes: number;
  };
  importDirectory: { rva: string; size: number } | null;
  delayImportPresent: boolean;
  sections: SectionInfo[];
  imports: ImportedDll[];
  notes: string[];
}

function readCStr(buf: Buffer, off: number, maxLen: number, what: string): string {
  let end = off;
  const limit = Math.min(buf.length, off + maxLen + 1);
  while (end < limit && buf[end] !== 0) end++;
  if (end >= buf.length) {
    throw err("UNTERMINATED_STRING", `${what} at file offset 0x${off.toString(16)} is not NUL-terminated before end of file`, {
      fileOffset: off,
    });
  }
  if (end - off > maxLen) {
    throw err("NAME_TOO_LONG", `${what} at file offset 0x${off.toString(16)} exceeds ${maxLen} bytes`, { fileOffset: off });
  }
  for (let i = off; i < end; i++) {
    if (buf[i] < 0x20 || buf[i] > 0x7e) {
      throw err("VALIDATION", `${what} at file offset 0x${off.toString(16)} contains non-ASCII byte 0x${buf[i].toString(16)}`, {
        fileOffset: i,
      });
    }
  }
  return buf.toString("ascii", off, end);
}

export function parsePe(buf: Buffer): PeReport {
  if (buf.length > LIMITS.maxFileSize) {
    throw err("FILE_TOO_LARGE", `File size ${buf.length} exceeds limit ${LIMITS.maxFileSize}`);
  }
  const need = (off: number, len: number, what: string) => {
    if (off < 0 || off + len > buf.length) {
      throw err("TRUNCATED", `${what}: need ${len} bytes at file offset 0x${off.toString(16)}, file size ${buf.length}`, {
        fileOffset: off,
      });
    }
  };

  // ---- DOS header ----
  need(0, 0x40, "DOS header");
  if (buf.readUInt16LE(0) !== 0x5a4d) throw err("BAD_DOS_HEADER", "Missing 'MZ' DOS magic", { fileOffset: 0 });
  const eLfanew = buf.readUInt32LE(0x3c);
  if (eLfanew < 0x40 || eLfanew > buf.length - 4) {
    throw err("BAD_ELFANEW", `e_lfanew 0x${eLfanew.toString(16)} points outside the file (size ${buf.length})`, {
      fileOffset: 0x3c,
    });
  }

  // ---- PE signature + COFF ----
  need(eLfanew, 24, "PE signature and COFF header");
  if (buf.readUInt32LE(eLfanew) !== 0x00004550) {
    throw err("BAD_PE_SIGNATURE", `Missing 'PE\\0\\0' signature at 0x${eLfanew.toString(16)}`, { fileOffset: eLfanew });
  }
  const coffOff = eLfanew + 4;
  const machine = buf.readUInt16LE(coffOff);
  if (machine !== IMAGE_FILE_MACHINE_AMD64) {
    throw err("UNSUPPORTED_MACHINE", `Machine 0x${machine.toString(16)} is not AMD64 (0x8664); 32-bit PE is unsupported`, {
      fileOffset: coffOff,
    });
  }
  const numberOfSections = buf.readUInt16LE(coffOff + 2);
  if (numberOfSections === 0 || numberOfSections > LIMITS.maxSections) {
    throw err("LIMIT_EXCEEDED", `NumberOfSections ${numberOfSections} outside allowed range 1..${LIMITS.maxSections}`, {
      fileOffset: coffOff + 2,
    });
  }
  const timeDateStamp = buf.readUInt32LE(coffOff + 4);
  const sizeOfOptionalHeader = buf.readUInt16LE(coffOff + 16);
  const characteristics = buf.readUInt16LE(coffOff + 18);

  // ---- Optional header (PE32+) ----
  const optOff = coffOff + 20;
  need(optOff, sizeOfOptionalHeader, "Optional header");
  if (sizeOfOptionalHeader < 112) {
    throw err("TRUNCATED", `SizeOfOptionalHeader ${sizeOfOptionalHeader} too small for PE32+`, { fileOffset: coffOff + 16 });
  }
  const magic = buf.readUInt16LE(optOff);
  if (magic !== IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    throw err("UNSUPPORTED_OPTIONAL_MAGIC", `Optional header magic 0x${magic.toString(16)} is not PE32+ (0x20b)`, {
      fileOffset: optOff,
    });
  }
  const imageBase = buf.readBigUInt64LE(optOff + 24);
  const sectionAlignment = buf.readUInt32LE(optOff + 32);
  const fileAlignment = buf.readUInt32LE(optOff + 36);
  const sizeOfImage = buf.readUInt32LE(optOff + 56);
  const sizeOfHeaders = buf.readUInt32LE(optOff + 60);
  const numberOfRvaAndSizes = buf.readUInt32LE(optOff + 108);

  const dirEntry = (idx: number): { rva: number; size: number } | null => {
    if (idx >= numberOfRvaAndSizes) return null;
    const off = optOff + 112 + idx * 8;
    if (off + 8 > optOff + sizeOfOptionalHeader) return null;
    return { rva: buf.readUInt32LE(off), size: buf.readUInt32LE(off + 4) };
  };
  const importDir = dirEntry(DIR_ENTRY_IMPORT);
  const delayDir = dirEntry(DIR_ENTRY_DELAY_IMPORT);
  const notes: string[] = [];
  if (delayDir && delayDir.rva !== 0) {
    notes.push("Delay-load import directory present but not parsed (unsupported feature).");
  }

  // ---- Section table ----
  const secOff = optOff + sizeOfOptionalHeader;
  need(secOff, numberOfSections * 40, "Section table");
  const sections: SectionInfo[] = [];
  for (let i = 0; i < numberOfSections; i++) {
    const o = secOff + i * 40;
    let nameEnd = o;
    while (nameEnd < o + 8 && buf[nameEnd] !== 0) nameEnd++;
    sections.push({
      index: i,
      name: buf.toString("ascii", o, nameEnd),
      virtualSize: buf.readUInt32LE(o + 8),
      virtualAddress: buf.readUInt32LE(o + 12),
      sizeOfRawData: buf.readUInt32LE(o + 16),
      pointerToRawData: buf.readUInt32LE(o + 20),
      characteristics: buf.readUInt32LE(o + 36),
    });
  }

  const mapper = new RvaMapper(sizeOfHeaders, sections, buf.length);

  // Map an RVA found at pointer file offset `ptrOff`; mapping failures are
  // re-thrown with the pointer's file offset attached for precise reporting.
  const mapAt = (rva: number, len: number, ptrOff: number) => {
    try {
      return mapper.mapSpan(rva, len);
    } catch (e: any) {
      if (e instanceof PeError && e.fileOffset === undefined) {
        throw err(e.code, e.message, { fileOffset: ptrOff, rva: e.rva });
      }
      throw e;
    }
  };

  const report: PeReport = {
    parserVersion: PARSER_VERSION,
    fileSize: buf.length,
    dosHeader: { eMagic: "MZ", eLfanew },
    coff: {
      machine: "0x8664 (AMD64)",
      numberOfSections,
      timeDateStamp,
      characteristics: `0x${characteristics.toString(16)}`,
    },
    optionalHeader: {
      magic: "0x20b (PE32+)",
      imageBase: `0x${imageBase.toString(16)}`,
      sectionAlignment,
      fileAlignment,
      sizeOfImage,
      sizeOfHeaders,
      numberOfRvaAndSizes,
    },
    importDirectory: importDir && importDir.rva !== 0 ? { rva: `0x${importDir.rva.toString(16)}`, size: importDir.size } : null,
    delayImportPresent: !!(delayDir && delayDir.rva !== 0),
    sections,
    imports: [],
    notes,
  };

  // ---- Import directory ----
  if (!importDir || importDir.rva === 0) {
    notes.push("No import directory: the image imports nothing. This is a valid state.");
    return report;
  }

  const descBase = mapAt(importDir.rva, 20, optOff + 112 + DIR_ENTRY_IMPORT * 8).fileOffset;
  let totalThunks = 0;
  for (let d = 0; ; d++) {
    if (d >= LIMITS.maxDescriptors) {
      throw err("DESCRIPTOR_NO_TERMINATOR", `No null import descriptor within ${LIMITS.maxDescriptors} entries`, {
        fileOffset: descBase,
      });
    }
    const dOff = descBase + d * 20;
    need(dOff, 20, `Import descriptor #${d}`);
    const oft = buf.readUInt32LE(dOff);
    const nameRva = buf.readUInt32LE(dOff + 12);
    const ft = buf.readUInt32LE(dOff + 16);
    if (oft === 0 && nameRva === 0 && ft === 0) break; // legal terminator

    if (nameRva === 0) {
      throw err("BAD_IMPORT_RVA", `Import descriptor #${d} has null Name RVA but is not a terminator`, { fileOffset: dOff + 12 });
    }
    const nameOff = mapAt(nameRva, 1, dOff + 12).fileOffset;
    const dllName = readCStr(buf, nameOff, LIMITS.maxDllName, "DLL name");

    const usedFallback = oft === 0;
    const thunkRva = usedFallback ? ft : oft;
    if (thunkRva === 0) {
      throw err("BAD_IMPORT_RVA", `Import descriptor #${d} for '${dllName}' has both OriginalFirstThunk and FirstThunk zero`, {
        fileOffset: dOff,
      });
    }
    const thunkBase = mapAt(thunkRva, 8, dOff + (usedFallback ? 16 : 0)).fileOffset;

    const functions: ImportedFunction[] = [];
    for (let t = 0; ; t++) {
      if (t >= LIMITS.maxThunksPerDescriptor) {
        throw err("THUNK_NO_TERMINATOR", `Thunk array for '${dllName}' has no null terminator within ${LIMITS.maxThunksPerDescriptor} entries`, {
          fileOffset: thunkBase,
        });
      }
      if (++totalThunks > LIMITS.maxTotalThunks) {
        throw err("LIMIT_EXCEEDED", `Total thunk count exceeds ${LIMITS.maxTotalThunks}`, { fileOffset: thunkBase });
      }
      const tOff = thunkBase + t * 8;
      need(tOff, 8, `Thunk #${t} for '${dllName}'`);
      const val = buf.readBigUInt64LE(tOff);
      if (val === 0n) break;
      const thunkRvaHere = thunkRva + t * 8;
      const src = usedFallback ? ("FirstThunk(fallback)" as const) : ("OriginalFirstThunk" as const);
      if ((val & ORDINAL_FLAG64) !== 0n) {
        // Use BigInt math only: the ordinal flag is bit 63, which signed
        // 32-bit bitwise operators cannot represent.
        functions.push({
          kind: "ordinal",
          ordinal: Number(val & 0xffffn),
          thunkValue: `0x${val.toString(16)}`,
          thunkFileOffset: tOff,
          thunkRva: `0x${thunkRvaHere.toString(16)}`,
          thunkSource: src,
        });
      } else {
        const nameRvaLow = Number(val & IMPORT_NAME_MASK64);
        if (nameRvaLow === 0) {
          throw err("BAD_IMPORT_RVA", `Thunk #${t} for '${dllName}' has zero name RVA`, { fileOffset: tOff });
        }
        const hnOff = mapAt(nameRvaLow, 2, tOff).fileOffset;
        const hint = buf.readUInt16LE(hnOff);
        const fname = readCStr(buf, hnOff + 2, LIMITS.maxFunctionName, "Function name");
        functions.push({
          kind: "name",
          name: fname,
          hint,
          thunkValue: `0x${val.toString(16)}`,
          thunkFileOffset: tOff,
          thunkRva: `0x${thunkRvaHere.toString(16)}`,
          thunkSource: src,
          nameFileOffset: hnOff,
        });
      }
    }

    report.imports.push({
      name: dllName,
      nameFileOffset: nameOff,
      descriptorFileOffset: dOff,
      originalFirstThunk: `0x${oft.toString(16)}`,
      firstThunk: `0x${ft.toString(16)}`,
      usedFallback,
      functions,
    });
  }

  return report;
}

/** Build a mapper for an already-parsed report (for RVA explanation queries). */
export function mapperFor(report: PeReport): RvaMapper {
  return new RvaMapper(report.optionalHeader.sizeOfHeaders, report.sections, report.fileSize);
}
