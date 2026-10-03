export const LIMITS = {
  /** Maximum accepted input file size. */
  maxFileSize: 64 * 1024 * 1024,
  /** Maximum number of COFF sections. */
  maxSections: 96,
  /** Maximum import descriptors before requiring a terminator. */
  maxDescriptors: 1024,
  /** Maximum thunks per descriptor. */
  maxThunksPerDescriptor: 65536,
  /** Maximum total thunks across all descriptors. */
  maxTotalThunks: 1 << 20,
  /** Maximum length of a DLL name (bytes, excluding NUL). */
  maxDllName: 260,
  /** Maximum length of an imported function name (bytes, excluding NUL). */
  maxFunctionName: 512,
} as const;

export const PARSER_VERSION = "1.0.0";
