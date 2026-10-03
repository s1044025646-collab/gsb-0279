export interface SectionInfo {
  name: string;
  virtualAddress: number;
  virtualSize: number;
  rawSize: number;
  rawOffset: number;
  characteristics: number;
}

export interface HeaderSummary {
  machine: number;
  machineName: string;
  numberOfSections: number;
  timeDateStamp: number;
  characteristics: number;
  imageBase: string;
  addressOfEntryPoint: number;
  sizeOfImage: number;
  sizeOfHeaders: number;
  subsystem: number;
  magic: number;
  peOffset: number;
  isPe32Plus: boolean;
}

export interface RvaMapping {
  rva: number;
  mappable: boolean;
  region: "header" | "section" | "unmapped" | "zero-fill";
  fileOffset: number | null;
  readableBytes: number;
  sectionName?: string;
  steps: string[];
  reason?: string;
}

export interface ImportedFunction {
  ordinal: number | null;
  name: string | null;
  hint: number | null;
  thunkRva: number;
  nameRva: number | null;
  sourceFileOffset: number | null;
  viaFallback: boolean;
}

export interface ImportedDll {
  name: string;
  nameRva: number;
  originalFirstThunk: number;
  firstThunk: number;
  usedThunk: "OriginalFirstThunk" | "FirstThunk";
  timeDateStamp: number;
  functions: ImportedFunction[];
}

export interface ParseWarning {
  code: string;
  message: string;
  rva?: number;
  fileOffset?: number;
}

export interface ImportReport {
  parserVersion: string;
  sha256: string;
  fileName: string;
  fileSize: number;
  header: HeaderSummary;
  sections: SectionInfo[];
  imports: ImportedDll[];
  hasImportDirectory: boolean;
  warnings: ParseWarning[];
  unsupported: string[];
}
