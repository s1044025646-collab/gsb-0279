/**
 * Byte-level builder for minimal synthetic PE32+ images.
 * Used by tests and the demo. Every structure is emitted with explicit,
 * precomputed offsets so tests can assert exact file offsets independently
 * of the parser.
 */

export interface SampleImport {
  dll: string;
  /** Name imports: [hint, name]. */
  names?: [number, string][];
  /** Ordinal imports. */
  ordinals?: number[];
  /** Force OriginalFirstThunk = 0 to exercise the FirstThunk fallback. */
  forceFallback?: boolean;
}

export interface SampleOptions {
  imports?: SampleImport[];
  /** Emit no import directory at all. */
  noImports?: boolean;
  /** Extra sections appended after .rdata. virtualAddress overrides auto-layout (for overlap tests). */
  extraSections?: { name: string; virtualSize: number; sizeOfRawData: number; virtualAddress?: number }[];
  /** Corrupt e_lfanew with this value. */
  badELfanew?: number;
  /** Truncate the file to this many bytes. */
  truncateTo?: number;
  /** Do not NUL-terminate the first function name (truncated-string test). */
  unterminatedName?: boolean;
}

export interface BuiltPe {
  buf: Buffer;
  /** Precomputed offsets for assertions. */
  layout: {
    eLfanew: number;
    importDirRva: number;
    descriptorFileOffset: number;
    thunkFileOffset: number;
    dllNameFileOffset: number;
    firstFuncNameFileOffset: number;
    rdataVirtualAddress: number;
    rdataPointerToRawData: number;
    sizeOfHeaders: number;
  };
}

const SECT_ALIGN = 0x1000;
const FILE_ALIGN = 0x200;

function align(v: number, a: number): number {
  return Math.ceil(v / a) * a;
}

export function buildSamplePe(opts: SampleOptions = {}): BuiltPe {
  const eLfanew = 0x80;
  const imports = opts.noImports ? [] : (opts.imports ?? []);
  const extra = opts.extraSections ?? [];
  const numSections = 1 + extra.length;

  // Header layout: DOS(0x80) + PE sig/COFF(24) + optional(0xF0) + sections.
  const optSize = 0xf0;
  const secTableOff = eLfanew + 4 + 20 + optSize;
  const sizeOfHeaders = align(secTableOff + numSections * 40, FILE_ALIGN);

  // .rdata section holds the import data.
  const rdataVA = 0x1000;
  const rdataRaw = sizeOfHeaders;

  // Lay out import structures inside .rdata (RVA-relative cursors).
  // Order: descriptors | thunks (OFT + IAT per dll) | hint/name | dll names.
  const descCount = imports.length;
  const descRva = rdataVA;
  let cursor = descRva + (descCount + 1) * 20;

  interface DllLayout {
    oftRva: number;
    iatRva: number;
    nameRva: number;
    hintNameRvas: number[];
  }
  const dlls: DllLayout[] = [];
  for (const imp of imports) {
    const n = (imp.names?.length ?? 0) + (imp.ordinals?.length ?? 0);
    const oftRva = cursor;
    cursor += (n + 1) * 8;
    const iatRva = cursor;
    cursor += (n + 1) * 8;
    const nameRva = cursor;
    cursor += imp.dll.length + 1;
    const hintNameRvas: number[] = [];
    for (const [, nm] of imp.names ?? []) {
      hintNameRvas.push(cursor);
      cursor += 2 + nm.length + 1;
    }
    dlls.push({ oftRva, iatRva, nameRva, hintNameRvas });
  }
  const rdataUsed = cursor - rdataVA;
  const rdataRawSize = Math.max(align(rdataUsed, FILE_ALIGN), FILE_ALIGN);

  // Extra sections.
  let nextVA = rdataVA + align(Math.max(rdataUsed, 1), SECT_ALIGN);
  let nextRaw = rdataRaw + rdataRawSize;
  const extraLayout = extra.map((s) => {
    const l = { va: s.virtualAddress ?? nextVA, raw: nextRaw, ...s };
    nextVA += align(Math.max(s.virtualSize, 1), SECT_ALIGN);
    nextRaw += align(s.sizeOfRawData, FILE_ALIGN);
    return l;
  });
  const sizeOfImage = nextVA;
  const totalSize = opts.truncateTo ?? nextRaw;

  const buf = Buffer.alloc(opts.truncateTo ? Math.max(opts.truncateTo, 0) : totalSize, 0);

  // ---- DOS header ----
  buf.writeUInt16LE(0x5a4d, 0); // 'MZ'
  buf.writeUInt32LE(opts.badELfanew ?? eLfanew, 0x3c);

  // ---- PE signature + COFF ----
  buf.writeUInt32LE(0x00004550, eLfanew); // 'PE\0\0'
  const coff = eLfanew + 4;
  buf.writeUInt16LE(0x8664, coff); // AMD64
  buf.writeUInt16LE(numSections, coff + 2);
  buf.writeUInt32LE(0x5f00_0001, coff + 4); // TimeDateStamp (fixed for determinism)
  buf.writeUInt16LE(optSize, coff + 16);
  buf.writeUInt16LE(0x2022, coff + 18); // EXECUTABLE | LARGE_ADDRESS_AWARE | DLL? -> exe characteristics

  // ---- Optional header (PE32+) ----
  const opt = coff + 20;
  buf.writeUInt16LE(0x20b, opt); // PE32+
  buf.writeBigUInt64LE(0x140000000n, opt + 24); // ImageBase
  buf.writeUInt32LE(SECT_ALIGN, opt + 32);
  buf.writeUInt32LE(FILE_ALIGN, opt + 36);
  buf.writeUInt32LE(sizeOfImage, opt + 56);
  buf.writeUInt32LE(sizeOfHeaders, opt + 60);
  buf.writeUInt32LE(2, opt + 68); // subsystem: CUI
  buf.writeUInt32LE(16, opt + 108); // NumberOfRvaAndSizes
  // Data directory #1: import table
  if (imports.length > 0) {
    buf.writeUInt32LE(descRva, opt + 112 + 8);
    buf.writeUInt32LE((descCount + 1) * 20, opt + 112 + 12);
  }

  // ---- Section table ----
  const writeSection = (i: number, name: string, vsize: number, va: number, rawSize: number, rawPtr: number, chars: number) => {
    const o = secTableOff + i * 40;
    buf.write(name, o, "ascii");
    buf.writeUInt32LE(vsize, o + 8);
    buf.writeUInt32LE(va, o + 12);
    buf.writeUInt32LE(rawSize, o + 16);
    buf.writeUInt32LE(rawPtr, o + 20);
    buf.writeUInt32LE(chars, o + 36);
  };
  writeSection(0, ".rdata", rdataUsed, rdataVA, rdataRawSize, rdataRaw, 0x40000040);
  extraLayout.forEach((s, i) =>
    writeSection(1 + i, s.name, s.virtualSize, s.va, s.sizeOfRawData, s.sizeOfRawData ? s.raw : 0, 0x40000040),
  );

  // ---- Import data in .rdata ----
  const rva2off = (rva: number) => rdataRaw + (rva - rdataVA);
  imports.forEach((imp, d) => {
    const L = dlls[d];
    const dOff = rva2off(descRva + d * 20);
    const useFallback = imp.forceFallback === true;
    buf.writeUInt32LE(useFallback ? 0 : L.oftRva, dOff); // OriginalFirstThunk
    buf.writeUInt32LE(L.nameRva, dOff + 12); // Name
    buf.writeUInt32LE(L.iatRva, dOff + 16); // FirstThunk

    const entries: bigint[] = [];
    (imp.names ?? []).forEach(([, ], i) => entries.push(BigInt(L.hintNameRvas[i])));
    (imp.ordinals ?? []).forEach((o) => entries.push(0x8000000000000000n | BigInt(o)));
    const thunkRva = useFallback ? L.iatRva : L.oftRva;
    entries.forEach((v, i) => buf.writeBigUInt64LE(v, rva2off(thunkRva + i * 8)));
    // IAT mirrors entries when not in fallback (content irrelevant to parser).
    if (!useFallback) entries.forEach((v, i) => buf.writeBigUInt64LE(v, rva2off(L.iatRva + i * 8)));

    (imp.names ?? []).forEach(([hint, nm], i) => {
      const o = rva2off(L.hintNameRvas[i]);
      buf.writeUInt16LE(hint, o);
      buf.write(nm, o + 2, "ascii");
      if (opts.unterminatedName && d === 0 && i === 0) {
        // Overwrite the NUL terminator and everything after with non-zero.
        for (let p = o + 2 + nm.length; p < buf.length; p++) buf[p] = 0x41;
      }
    });
    buf.write(imp.dll, rva2off(L.nameRva), "ascii");
  });

  const firstDll = dlls[0];
  return {
    buf,
    layout: {
      eLfanew,
      importDirRva: descRva,
      descriptorFileOffset: rva2off(descRva),
      thunkFileOffset: firstDll ? rva2off(imports[0]?.forceFallback ? firstDll.iatRva : firstDll.oftRva) : 0,
      dllNameFileOffset: firstDll ? rva2off(firstDll.nameRva) : 0,
      firstFuncNameFileOffset: firstDll && firstDll.hintNameRvas.length ? rva2off(firstDll.hintNameRvas[0]) : 0,
      rdataVirtualAddress: rdataVA,
      rdataPointerToRawData: rdataRaw,
      sizeOfHeaders,
    },
  };
}
