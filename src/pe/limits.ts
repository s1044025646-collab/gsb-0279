export const LIMITS = {
  maxFileSize: 64 * 1024 * 1024,
  maxSections: 96,
  maxDescriptors: 4096,
  maxThunks: 1_000_000,
  maxNameLength: 1024,
  maxDllNameLength: 1024,
  sizeOfHeadersMax: 0x400 * 16,
} as const;

export const PARSER_VERSION = "1.0.0";
