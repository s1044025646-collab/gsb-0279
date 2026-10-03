export type ErrorCode =
  | "FILE_TOO_LARGE"
  | "FILE_EMPTY"
  | "BAD_DOS_SIGNATURE"
  | "BAD_PE_OFFSET"
  | "BAD_PE_SIGNATURE"
  | "TRUNCATED_HEADER"
  | "UNSUPPORTED_MACHINE"
  | "UNSUPPORTED_OPTIONAL_MAGIC"
  | "TOO_MANY_SECTIONS"
  | "TRUNCATED_SECTION_TABLE"
  | "INVALID_SECTION"
  | "OVERLAPPING_SECTIONS"
  | "BAD_RVA"
  | "VIRTUAL_ZERO_FILL"
  | "TRUNCATED_READ"
  | "BAD_IMPORT_DIRECTORY"
  | "IMPORT_DESCRIPTOR_TRUNCATED"
  | "IMPORT_MISSING_TERMINATOR"
  | "TOO_MANY_DESCRIPTORS"
  | "TOO_MANY_THUNKS"
  | "BAD_THUNK"
  | "NAME_TOO_LONG"
  | "UNSUPPORTED_BOUND_IMPORT"
  | "UNSUPPORTED_DELAY_IMPORT"
  | "NOT_PE32_PLUS"
  | "INTERNAL";

export class PeError extends Error {
  readonly code: ErrorCode;
  readonly fileOffset?: number;
  readonly rva?: number;
  readonly details?: Record<string, number | string | boolean>;

  constructor(
    code: ErrorCode,
    message: string,
    ctx: { fileOffset?: number; rva?: number; details?: Record<string, number | string | boolean> } = {},
  ) {
    super(message);
    this.name = "PeError";
    this.code = code;
    this.fileOffset = ctx.fileOffset;
    this.rva = ctx.rva;
    this.details = ctx.details;
  }

  toJSON(): Record<string, unknown> {
    return {
      code: this.code,
      message: this.message,
      fileOffset: this.fileOffset,
      rva: this.rva,
      details: this.details,
    };
  }
}
