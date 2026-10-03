import { PeBuilder, RawSection, R, RVA, ORDINAL_FLAG, normalSections } from "./builder.js";

export function normalNameImport(): Buffer {
  const b = new PeBuilder({ sections: normalSections(), fileSize: 0x600, importDirRva: RVA.desc, importDirSize: 40 });
  // ILT: name import + ordinal 7 + terminator
  b.u64(R.iltOff + 0, BigInt(RVA.hintName));
  b.u64(R.iltOff + 8, ORDINAL_FLAG | 7n);
  b.u64(R.iltOff + 16, 0n);
  // IAT mirrors ILT (bound values same since never bound)
  b.u64(R.iatOff + 0, BigInt(RVA.hintName));
  b.u64(R.iatOff + 8, ORDINAL_FLAG | 7n);
  b.u64(R.iatOff + 16, 0n);
  // names
  b.ascii(R.dllNameOff, "test.dll");
  b.u16(R.hintNameOff, 1);
  b.ascii(R.hintNameOff + 2, "MyExport");
  // descriptor + terminator
  b.u32(R.descOff + 0, RVA.ilt); // OriginalFirstThunk
  b.u32(R.descOff + 4, 0); // timeDateStamp
  b.u32(R.descOff + 8, 0); // ForwarderChain
  b.u32(R.descOff + 12, RVA.dllName); // Name
  b.u32(R.descOff + 16, RVA.iat); // FirstThunk
  return b.build();
}

export function ordinalOnly(): Buffer {
  const b = new PeBuilder({ sections: normalSections(), fileSize: 0x600, importDirRva: RVA.desc });
  b.u64(R.iltOff, ORDINAL_FLAG | 42n);
  b.u64(R.iltOff + 8, 0n);
  b.u64(R.iatOff, ORDINAL_FLAG | 42n);
  b.u64(R.iatOff + 8, 0n);
  b.ascii(R.dllNameOff, "ord.dll");
  b.u32(R.descOff + 0, RVA.ilt);
  b.u32(R.descOff + 12, RVA.dllName);
  b.u32(R.descOff + 16, RVA.iat);
  return b.build();
}

export function thunkFallback(): Buffer {
  const b = new PeBuilder({ sections: normalSections(), fileSize: 0x600, importDirRva: RVA.desc });
  // OriginalFirstThunk absent (0); only FirstThunk populated
  b.u64(R.iatOff, BigInt(RVA.hintName));
  b.u64(R.iatOff + 8, 0n);
  b.ascii(R.dllNameOff, "fb.dll");
  b.u16(R.hintNameOff, 3);
  b.ascii(R.hintNameOff + 2, "FallbackFunc");
  b.u32(R.descOff + 0, 0);
  b.u32(R.descOff + 12, RVA.dllName);
  b.u32(R.descOff + 16, RVA.iat);
  return b.build();
}

export function noImports(): Buffer {
  const b = new PeBuilder({ sections: normalSections(), fileSize: 0x600 });
  return b.build();
}

export function zeroFillBss(): Buffer {
  const sections: RawSection[] = [
    { name: ".text", virtualAddress: 0x1000, virtualSize: 0x200, rawOffset: 0x200, rawSize: 0x200 },
    { name: ".rdata", virtualAddress: 0x2000, virtualSize: 0x200, rawOffset: 0x400, rawSize: 0x200 },
    { name: ".bss", virtualAddress: 0x3000, virtualSize: 0x1000, rawOffset: 0, rawSize: 0 },
  ];
  return new PeBuilder({ sections, fileSize: 0x600, sizeOfImage: 0x5000 }).build();
}

export function overlappingSections(): Buffer {
  const sections: RawSection[] = [
    { name: ".text", virtualAddress: 0x1000, virtualSize: 0x200, rawOffset: 0x200, rawSize: 0x200 },
    { name: ".rdata", virtualAddress: 0x2000, virtualSize: 0x200, rawOffset: 0x400, rawSize: 0x200 },
    // .ovl raw bytes point into .rdata file area and its VA overlaps .rdata tail
    { name: ".ovl", virtualAddress: 0x2100, virtualSize: 0x100, rawOffset: 0x500, rawSize: 0x100 },
  ];
  return new PeBuilder({ sections, fileSize: 0x600 }).build();
}

export function badPeOffset(): Buffer {
  // valid MZ but e_lfanew points past end
  const b = new PeBuilder({ sections: normalSections(), fileSize: 0x600 });
  b.u32(0x3c, 0x5000);
  return b.build();
}

export function truncatedNameString(): Buffer {
  // hint/name 位于节原始数据最末，函数字节后没有零终止符
  const sections: RawSection[] = [
    { name: ".text", virtualAddress: 0x1000, virtualSize: 0x200, rawOffset: 0x200, rawSize: 0x200 },
    { name: ".rdata", virtualAddress: 0x2000, virtualSize: 0x100, rawOffset: 0x400, rawSize: 0x84 },
  ];
  const b = new PeBuilder({ sections, fileSize: 0x484, importDirRva: 0x2000 });
  // descriptor at raw 0x400, terminator at 0x414
  b.u32(0x400 + 0, 0x2020); // OriginalFirstThunk
  b.u32(0x400 + 12, 0x2070); // DLL name RVA
  b.u32(0x400 + 16, 0x2020); // FirstThunk
  // thunk table at raw 0x420 (rva 0x2020): one name entry + null
  b.u64(0x420, BigInt(0x2080));
  b.u64(0x428, 0n);
  b.ascii(0x470, "trunc.dll"); // rva 0x2070
  // hint/name at raw 0x480 (rva 0x2080): hint + 12 name bytes, no terminator, ends file
  b.u16(0x480, 9);
  b.ascii(0x482, "NoTerminator", false);
  return b.build();
}

export function badImportRva(): Buffer {
  // import directory RVA points into nowhere (no section covers 0x9000)
  return new PeBuilder({ sections: normalSections(), fileSize: 0x600, importDirRva: 0x9000, importDirSize: 20 }).build();
}

export function missingTerminator(): Buffer {
  // directory starts at 0x21e0 (last descriptor-sized slot); descriptor valid,
  // following terminator slot is outside raw bytes => must be diagnosed as missing terminator.
  const sections: RawSection[] = [
    { name: ".text", virtualAddress: 0x1000, virtualSize: 0x200, rawOffset: 0x200, rawSize: 0x200 },
    { name: ".rdata", virtualAddress: 0x2000, virtualSize: 0x200, rawOffset: 0x400, rawSize: 0x1f4 },
  ];
  const b = new PeBuilder({ sections, fileSize: 0x600, importDirRva: 0x21e0 });
  const descRaw = 0x400 + 0x1e0; // 0x5e0
  b.u32(descRaw + 0, 0); // OriginalFirstThunk=0 -> fallback
  b.u32(descRaw + 12, RVA.dllName);
  b.u32(descRaw + 16, RVA.ilt);
  b.ascii(R.dllNameOff, "end.dll");
  b.u64(R.iatOff, 0n);
  return b.build();
}

export function pe32NotSupported(): Buffer {
  return new PeBuilder({ sections: normalSections(), fileSize: 0x600, optionalMagic: 0x10b, machine: 0x14c }).build();
}

export const ALL_FIXTURES: Record<string, () => Buffer> = {
  "normal-name-import.exe": normalNameImport,
  "ordinal-only.exe": ordinalOnly,
  "thunk-fallback.exe": thunkFallback,
  "no-imports.exe": noImports,
  "zero-fill-bss.exe": zeroFillBss,
  "overlapping-sections.exe": overlappingSections,
  "bad-pe-offset.exe": badPeOffset,
  "truncated-name.exe": truncatedNameString,
  "bad-import-rva.exe": badImportRva,
  "missing-terminator.exe": missingTerminator,
  "pe32-unsupported.exe": pe32NotSupported,
};
