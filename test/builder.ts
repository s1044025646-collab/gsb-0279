import { Buffer } from "node:buffer";

export interface RawSection {
  name: string;
  virtualAddress: number;
  virtualSize: number;
  rawOffset: number;
  rawSize: number;
  characteristics?: number;
}

export interface BuildOptions {
  sections: RawSection[];
  fileSize: number;
  importDirRva?: number;
  importDirSize?: number;
  imageBase?: bigint;
  addressOfEntryPoint?: number;
  sizeOfImage?: number;
  sizeOfHeaders?: number;
  delayDirRva?: number;
  delayDirSize?: number;
  peOffset?: number;
  machine?: number;
  optionalMagic?: number;
}

export class PeBuilder {
  buf: Buffer;
  private readonly peOffset: number;

  constructor(opts: BuildOptions) {
    this.buf = Buffer.alloc(opts.fileSize, 0);
    const peOffset = opts.peOffset ?? 0x40;
    this.peOffset = peOffset;
    const sizeOfHeaders = opts.sizeOfHeaders ?? 0x200;

    this.buf.writeUInt16LE(0x5a4d, 0);
    this.buf.writeUInt32LE(peOffset, 0x3c);

    this.buf.writeUInt32LE(0x00004550, peOffset);
    const coff = peOffset + 4;
    this.buf.writeUInt16LE(opts.machine ?? 0x8664, coff + 0);
    this.buf.writeUInt16LE(opts.sections.length, coff + 2);
    this.buf.writeUInt32LE(0x12345678, coff + 4);
    this.buf.writeUInt16LE(0x0022, coff + 18);

    const opt = coff + 20;
    this.buf.writeUInt16LE(opts.optionalMagic ?? 0x20b, opt);
    this.buf.writeUInt32LE(opts.addressOfEntryPoint ?? 0x1000, opt + 16);
    this.buf.writeBigUInt64LE(opts.imageBase ?? 0x140000000n, opt + 24);
    this.buf.writeUInt32LE(0x1000, opt + 32);
    this.buf.writeUInt32LE(0x200, opt + 36);
    this.buf.writeUInt32LE(opts.sizeOfImage ?? 0x5000, opt + 56);
    this.buf.writeUInt32LE(sizeOfHeaders, opt + 60);
    this.buf.writeUInt16LE(3, opt + 68);
    this.buf.writeUInt32LE(16, opt + 108);

    const dirBase = opt + 112;
    if (opts.importDirRva !== undefined) {
      this.buf.writeUInt32LE(opts.importDirRva, dirBase + 1 * 8);
      this.buf.writeUInt32LE(opts.importDirSize ?? 0, dirBase + 1 * 8 + 4);
    }
    if (opts.delayDirRva !== undefined) {
      this.buf.writeUInt32LE(opts.delayDirRva, dirBase + 13 * 8);
      this.buf.writeUInt32LE(opts.delayDirSize ?? 0, dirBase + 13 * 8 + 4);
    }

    const sectionStart = opt + 240;
    opts.sections.forEach((s, i) => {
      const so = sectionStart + i * 40;
      this.buf.write(s.name, so, 8, "ascii");
      this.buf.writeUInt32LE(s.virtualSize, so + 8);
      this.buf.writeUInt32LE(s.virtualAddress, so + 12);
      this.buf.writeUInt32LE(s.rawSize, so + 16);
      this.buf.writeUInt32LE(s.rawOffset, so + 20);
      this.buf.writeUInt32LE(s.characteristics ?? 0x60000020, so + 36);
    });
  }

  u32(off: number, v: number): this {
    this.buf.writeUInt32LE(v >>> 0, off);
    return this;
  }

  u64(off: number, v: bigint): this {
    this.buf.writeBigUInt64LE(v, off);
    return this;
  }

  u16(off: number, v: number): this {
    this.buf.writeUInt16LE(v, off);
    return this;
  }

  ascii(off: number, text: string, includeNul = true): this {
    this.buf.write(text, off, text.length, "ascii");
    if (includeNul) this.buf.writeUInt8(0, off + text.length);
    return this;
  }

  fill(off: number, len: number, byte: number): this {
    this.buf.fill(byte, off, off + len);
    return this;
  }

  build(): Buffer {
    return Buffer.from(this.buf);
  }
}

export const R = {
  descOff: 0x400,
  iltOff: 0x440,
  iatOff: 0x480,
  dllNameOff: 0x4c0,
  hintNameOff: 0x4e0,
};

export const RVA = {
  rdata: 0x2000,
  desc: 0x2000,
  ilt: 0x2040,
  iat: 0x2080,
  dllName: 0x20c0,
  hintName: 0x20e0,
};

export const ORDINAL_FLAG = 0x8000000000000000n;

export function normalSections(): RawSection[] {
  return [
    { name: ".text", virtualAddress: 0x1000, virtualSize: 0x200, rawOffset: 0x200, rawSize: 0x200 },
    { name: ".rdata", virtualAddress: 0x2000, virtualSize: 0x200, rawOffset: 0x400, rawSize: 0x200 },
  ];
}

export function writeNameImport(b: PeBuilder, iltOrIatOff: number, hintNameRva: number): void {
  b.u64(iltOrIatOff, BigInt(hintNameRva));
}
