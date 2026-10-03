export type PeErrorCode =
  | "FILE_TOO_LARGE"
  | "TRUNCATED"
  | "BAD_DOS_HEADER"
  | "BAD_ELFANEW"
  | "BAD_PE_SIGNATURE"
  | "UNSUPPORTED_MACHINE"
  | "UNSUPPORTED_OPTIONAL_MAGIC"
  | "UNSUPPORTED_DELAY_IMPORT"
  | "RVA_UNMAPPED"
  | "RVA_ZERO_FILL"
  | "RVA_AMBIGUOUS"
  | "SPAN_CROSSES_REGION"
  | "NAME_TOO_LONG"
  | "UNTERMINATED_STRING"
  | "LIMIT_EXCEEDED"
  | "DESCRIPTOR_NO_TERMINATOR"
  | "THUNK_NO_TERMINATOR"
  | "BAD_IMPORT_RVA"
  | "VALIDATION";

export class PeError extends Error {
  readonly code: PeErrorCode;
  /** Absolute file offset related to the failure, when known. */
  readonly fileOffset?: number;
  /** RVA related to the failure, when known. */
  readonly rva?: bigint;

  constructor(code: PeErrorCode, message: string, opts: { fileOffset?: number; rva?: bigint } = {}) {
    super(message);
    this.name = "PeError";
    this.code = code;
    this.fileOffset = opts.fileOffset;
    this.rva = opts.rva;
  }
}

export function err(code: PeErrorCode, message: string, opts: { fileOffset?: number; rva?: bigint } = {}): PeError {
  return new PeError(code, message, opts);
}
