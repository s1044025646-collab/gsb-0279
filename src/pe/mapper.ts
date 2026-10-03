import { PeError } from "./errors.js";
import type { RvaMapping, SectionInfo } from "./types.js";

export class RvaMapper {
  readonly sections: SectionInfo[];
  readonly sizeOfHeaders: number;
  readonly rawHeadersSize: number;
  readonly fileSize: number;
  readonly overlapSections: string[][];

  constructor(sections: SectionInfo[], sizeOfHeaders: number, fileSize: number) {
    this.sections = sections;
    this.sizeOfHeaders = sizeOfHeaders;
    this.rawHeadersSize = Math.min(sizeOfHeaders, fileSize);
    this.fileSize = fileSize;
    this.overlapSections = this.detectOverlaps();
  }

  private detectOverlaps(): string[][] {
    const pairs: string[][] = [];
    for (let i = 0; i < this.sections.length; i++) {
      for (let j = i + 1; j < this.sections.length; j++) {
        const a = this.sections[i]!;
        const b = this.sections[j]!;
        const aVS = Math.max(a.virtualSize, a.rawSize);
        const bVS = Math.max(b.virtualSize, b.rawSize);
        const vOverlap = a.virtualAddress < b.virtualAddress + bVS && b.virtualAddress < a.virtualAddress + aVS;
        const aRawEnd = a.rawOffset + a.rawSize;
        const bRawEnd = b.rawOffset + b.rawSize;
        const rawOverlap =
          a.rawSize > 0 && b.rawSize > 0 && a.rawOffset < bRawEnd && b.rawOffset < aRawEnd;
        if (vOverlap || rawOverlap) pairs.push([a.name, b.name]);
      }
    }
    return pairs;
  }

  findSection(rva: number): SectionInfo[] {
    return this.sections.filter((s) => {
      const span = Math.max(s.virtualSize, s.rawSize);
      return rva >= s.virtualAddress && rva < s.virtualAddress + span;
    });
  }

  explain(rva: number, length = 1): RvaMapping {
    const steps: string[] = [`输入 RVA=0x${rva.toString(16)}，需要读取 ${length} 字节`];

    if (!Number.isInteger(rva) || rva < 0) {
      return { rva, mappable: false, region: "unmapped", fileOffset: null, readableBytes: 0, steps, reason: "RVA 非法" };
    }

    if (rva < this.sizeOfHeaders) {
      if (rva + length <= this.rawHeadersSize) {
        steps.push(`RVA 落在头部区 [0, 0x${this.sizeOfHeaders.toString(16)})，头部按恒等映射`);
        steps.push(`文件偏移 = RVA = 0x${rva.toString(16)}`);
        return { rva, mappable: true, region: "header", fileOffset: rva, readableBytes: this.rawHeadersSize - rva, steps };
      }
      steps.push("RVA 位于头部区，但磁盘头部原始数据不足，属于头部零填充（无实际磁盘字节）");
      return { rva, mappable: false, region: "zero-fill", fileOffset: null, readableBytes: 0, steps, reason: "头部 SizeOfHeaders 超出磁盘实际字节" };
    }

    const matched = this.findSection(rva);
    if (matched.length === 0) {
      steps.push("RVA 不属于头部，也不落在任何节的虚拟区间内");
      return { rva, mappable: false, region: "unmapped", fileOffset: null, readableBytes: 0, steps, reason: "无匹配的头或节" };
    }

    if (matched.length > 1) {
      const names = matched.map((s) => s.name).join(", ");
      steps.push(`检测到歧义：RVA 同时落在多个节（${names}），拒绝映射`);
      return { rva, mappable: false, region: "unmapped", fileOffset: null, readableBytes: 0, steps, reason: `重叠节导致多重映射: ${names}` };
    }

    const s = matched[0]!;
    const delta = rva - s.virtualAddress;
    steps.push(`RVA 落在节 ${s.name}（VA=0x${s.virtualAddress.toString(16)}, VS=0x${s.virtualSize.toString(16)}, PR=0x${s.rawOffset.toString(16)}, SR=0x${s.rawSize.toString(16)}）`);
    steps.push(`节内偏移 delta = RVA - VirtualAddress = 0x${delta.toString(16)}`);

    if (s.rawSize > 0 && delta < s.rawSize) {
      const fileOffset = s.rawOffset + delta;
      const avail = Math.min(s.rawSize - delta, this.fileSize - fileOffset);
      if (fileOffset + length <= this.fileSize && length <= s.rawSize - delta) {
        steps.push(`文件偏移 = PointerToRawData + delta = 0x${fileOffset.toString(16)}`);
        return { rva, mappable: true, region: "section", fileOffset, readableBytes: Math.max(avail, 0), sectionName: s.name, steps };
      }
      steps.push("节原始数据跨度不足，读取会越过文件末尾");
      return { rva, mappable: false, region: "unmapped", fileOffset: null, readableBytes: 0, sectionName: s.name, steps, reason: "完整数据跨度超出文件" };
    }

    if (delta < s.virtualSize) {
      steps.push("delta 超出 SizeOfRawData 但在 VirtualSize 内：该区域由加载器零填充，磁盘无对应字节");
      return { rva, mappable: false, region: "zero-fill", fileOffset: null, readableBytes: 0, sectionName: s.name, steps, reason: "虚拟零填充（bss），无磁盘字节" };
    }

    steps.push("delta 超出节范围");
    return { rva, mappable: false, region: "unmapped", fileOffset: null, readableBytes: 0, sectionName: s.name, steps, reason: "超出节虚拟大小" };
  }

  resolve(rva: number, length: number): number {
    const m = this.explain(rva, length);
    if (!m.mappable || m.fileOffset === null) {
      throw new PeError(
        m.region === "zero-fill" ? "VIRTUAL_ZERO_FILL" : "BAD_RVA",
        m.reason ?? "RVA 无法映射到磁盘文件偏移",
        { rva, details: { region: m.region, section: m.sectionName ?? "" } },
      );
    }
    return m.fileOffset;
  }
}
