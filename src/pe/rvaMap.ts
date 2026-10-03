import { err } from "./errors.js";

export interface SectionInfo {
  index: number;
  name: string;
  virtualAddress: number;
  virtualSize: number;
  sizeOfRawData: number;
  pointerToRawData: number;
  characteristics: number;
}

export type MapSource = "headers" | "section";

export interface MapStep {
  source: MapSource;
  sectionIndex?: number;
  sectionName?: string;
  rva: string;
  regionVirtualStart: string;
  delta: string;
  regionFileStart: string;
  fileOffset: number;
}

export interface MapResult {
  fileOffset: number;
  step: MapStep;
}

/**
 * Restricted RVA -> file-offset mapper for PE32+ images.
 *
 * Rules:
 *  - RVAs below SizeOfHeaders map 1:1 into the on-disk header area.
 *  - RVAs inside a section map via (PointerToRawData + (rva - VirtualAddress)),
 *    but only while the delta is smaller than SizeOfRawData (real disk bytes).
 *  - Deltas in [SizeOfRawData, VirtualSize) are virtual zero-fill: no disk
 *    bytes exist and reads are rejected with RVA_ZERO_FILL.
 *  - If more than one region claims an RVA, the mapping is ambiguous and is
 *    rejected with RVA_AMBIGUOUS.
 */
export class RvaMapper {
  constructor(
    private readonly sizeOfHeaders: number,
    private readonly sections: SectionInfo[],
    private readonly fileSize: number,
  ) {}

  private claimants(rva: number): { source: MapSource; section?: SectionInfo }[] {
    const out: { source: MapSource; section?: SectionInfo }[] = [];
    if (rva < this.sizeOfHeaders) out.push({ source: "headers" });
    for (const s of this.sections) {
      const span = Math.max(s.virtualSize, s.sizeOfRawData);
      if (span === 0) continue;
      if (rva >= s.virtualAddress && rva - s.virtualAddress < span) {
        out.push({ source: "section", section: s });
      }
    }
    return out;
  }

  /** Map a single RVA to a file offset, or throw a PeError with the reason. */
  map(rva: number): MapResult {
    if (!Number.isSafeInteger(rva) || rva < 0) {
      throw err("RVA_UNMAPPED", `RVA ${rva} is not a valid non-negative safe integer`);
    }
    const c = this.claimants(rva);
    if (c.length === 0) {
      throw err("RVA_UNMAPPED", `RVA 0x${rva.toString(16)} is not covered by headers or any section`, { rva: BigInt(rva) });
    }
    if (c.length > 1) {
      const who = c.map((x) => (x.source === "headers" ? "headers" : `section '${x.section!.name}'`)).join(", ");
      throw err("RVA_AMBIGUOUS", `RVA 0x${rva.toString(16)} is claimed by multiple regions: ${who}`, { rva: BigInt(rva) });
    }
    const one = c[0];
    if (one.source === "headers") {
      if (rva >= this.fileSize) {
        throw err("TRUNCATED", `Header RVA 0x${rva.toString(16)} maps past end of file (size ${this.fileSize})`, {
          fileOffset: rva,
          rva: BigInt(rva),
        });
      }
      return {
        fileOffset: rva,
        step: {
          source: "headers",
          rva: `0x${rva.toString(16)}`,
          regionVirtualStart: "0x0",
          delta: `0x${rva.toString(16)}`,
          regionFileStart: "0x0",
          fileOffset: rva,
        },
      };
    }
    const s = one.section!;
    const delta = rva - s.virtualAddress;
    if (delta >= s.sizeOfRawData) {
      throw err(
        "RVA_ZERO_FILL",
        `RVA 0x${rva.toString(16)} lies in virtual zero-fill of section '${s.name}' ` +
          `(delta 0x${delta.toString(16)} >= SizeOfRawData 0x${s.sizeOfRawData.toString(16)}); no disk bytes exist`,
        { rva: BigInt(rva) },
      );
    }
    const off = s.pointerToRawData + delta;
    if (off >= this.fileSize) {
      throw err(
        "TRUNCATED",
        `RVA 0x${rva.toString(16)} maps to file offset 0x${off.toString(16)} past end of file (size ${this.fileSize})`,
        { fileOffset: off, rva: BigInt(rva) },
      );
    }
    return {
      fileOffset: off,
      step: {
        source: "section",
        sectionIndex: s.index,
        sectionName: s.name,
        rva: `0x${rva.toString(16)}`,
        regionVirtualStart: `0x${s.virtualAddress.toString(16)}`,
        delta: `0x${delta.toString(16)}`,
        regionFileStart: `0x${s.pointerToRawData.toString(16)}`,
        fileOffset: off,
      },
    };
  }

  /**
   * Map a full span [rva, rva+length). The whole span must live inside one
   * contiguous file-backed region; partial mappings are rejected.
   */
  mapSpan(rva: number, length: number): MapResult {
    if (length < 0) throw err("VALIDATION", `Negative span length ${length}`);
    const first = this.map(rva);
    if (length === 0) return first;
    const last = this.map(rva + length - 1);
    if (last.fileOffset - first.fileOffset !== length - 1) {
      throw err(
        "SPAN_CROSSES_REGION",
        `Span RVA 0x${rva.toString(16)}..0x${(rva + length).toString(16)} crosses a region boundary`,
        { rva: BigInt(rva) },
      );
    }
    if (first.fileOffset + length > this.fileSize) {
      throw err("TRUNCATED", `Span at file offset 0x${first.fileOffset.toString(16)} length ${length} exceeds file size`, {
        fileOffset: first.fileOffset,
        rva: BigInt(rva),
      });
    }
    return first;
  }

  /** Explain how an RVA maps (or why it does not) without throwing. */
  explain(rva: number): { ok: boolean; rva: string; step?: MapStep; error?: { code: string; message: string } } {
    try {
      const r = this.map(rva);
      return { ok: true, rva: `0x${rva.toString(16)}`, step: r.step };
    } catch (e: any) {
      return { ok: false, rva: `0x${rva.toString(16)}`, error: { code: e.code ?? "ERROR", message: e.message } };
    }
  }
}
