import { PeError } from "./errors.js";

export class BlobReader {
  readonly buf: Buffer;
  get size(): number {
    return this.buf.length;
  }

  constructor(buf: Buffer) {
    this.buf = buf;
  }

  private checkSpan(offset: number, length: number): void {
    if (!Number.isInteger(offset) || offset < 0) {
      throw new PeError("BAD_RVA", `非法偏移 ${offset}`, { fileOffset: offset });
    }
    if (offset + length > this.buf.length) {
      throw new PeError(
        "TRUNCATED_READ",
        `需要文件偏移 0x${offset.toString(16)} 起 ${length} 字节，但文件仅有 ${this.buf.length} 字节`,
        { fileOffset: offset, details: { need: length, fileSize: this.buf.length } },
      );
    }
  }

  u8(offset: number): number {
    this.checkSpan(offset, 1);
    return this.buf.readUInt8(offset);
  }

  u16(offset: number): number {
    this.checkSpan(offset, 2);
    return this.buf.readUInt16LE(offset);
  }

  u32(offset: number): number {
    this.checkSpan(offset, 4);
    return this.buf.readUInt32LE(offset);
  }

  u64(offset: number): bigint {
    this.checkSpan(offset, 8);
    return this.buf.readBigUInt64LE(offset);
  }

  bytes(offset: number, length: number): Buffer {
    this.checkSpan(offset, length);
    return this.buf.subarray(offset, offset + length);
  }

  slice(offset: number, length: number): BlobReader {
    return new BlobReader(this.bytes(offset, length));
  }

  readCString(offset: number, maxLength: number, errCode: "NAME_TOO_LONG" = "NAME_TOO_LONG"): { text: string; endOffset: number; rawLength: number } {
    let end = offset;
    while (end < this.buf.length && this.buf.readUInt8(end) !== 0) {
      if (end - offset >= maxLength) {
        throw new PeError(errCode, `字符串超过最大长度 ${maxLength}`, { fileOffset: offset });
      }
      end++;
    }
    if (end >= this.buf.length) {
      throw new PeError(
        "TRUNCATED_READ",
        `零终止字符串在文件偏移 0x${offset.toString(16)} 处被截断（文件结束前未遇到终止符）`,
        { fileOffset: offset },
      );
    }
    const rawLength = end - offset;
    const text = this.buf.subarray(offset, end).toString("ascii");
    return { text, endOffset: end, rawLength };
  }
}
