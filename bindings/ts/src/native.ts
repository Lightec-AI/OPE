import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import koffi from "koffi";

export const OPE_OK = 0;
export const OPE_ERR_VERIFY = -5;

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export class OpeError extends Error {
  constructor(
    message: string,
    readonly code: number,
  ) {
    super(message);
    this.name = "OpeError";
  }
}

export class VerifyError extends OpeError {
  constructor(message: string, code: number) {
    super(message, code);
    this.name = "VerifyError";
  }
}

export function libPath(): string {
  const env = process.env.OPE_LIB_PATH;
  if (env) {
    return env;
  }
  const root = path.resolve(__dirname, "../../..");
  const base = path.join(root, "target");
  const names: Record<string, string> = {
    darwin: "libope_ffi.dylib",
    linux: "libope_ffi.so",
    win32: "ope_ffi.dll",
  };
  const name = names[process.platform];
  if (!name) {
    throw new OpeError(`unsupported platform: ${process.platform}`, -1);
  }
  const release = path.join(base, "release", name);
  if (fs.existsSync(release)) {
    return release;
  }
  const debug = path.join(base, "debug", name);
  if (fs.existsSync(debug)) {
    return debug;
  }
  throw new OpeError(
    `native library not found; run: cargo build -p ope-ffi --release`,
    -1,
  );
}

const lib = koffi.load(libPath());

const ope_version = lib.func("const char *ope_version()");
const ope_last_error_message = lib.func("int ope_last_error_message(char *buf, size_t buflen)");
const ope_string_free = lib.func("void ope_string_free(char *s)");
// Use void* so koffi returns a real pointer (char* is auto-copied to JS string).
const ope_envelope_sign_alloc = lib.func(
  "void *ope_envelope_sign_alloc(const uint8_t *secret_key, const char *json_in)",
);
const ope_envelope_verify = lib.func(
  "int ope_envelope_verify(const uint8_t *public_key, const char *json, uint32_t max_skew_secs)",
);
const ope_envelope_verify_dev_json = lib.func(
  "int ope_envelope_verify_dev_json(const char *json)",
);

export function version(): string {
  return ope_version() as string;
}

export function lastError(): string {
  const buf = Buffer.alloc(512);
  ope_last_error_message(buf, buf.length);
  return buf.toString("utf8").replace(/\0.*$/, "");
}

function keyBuffer(key: Uint8Array): Buffer {
  if (key.length !== 32) {
    throw new OpeError("key must be 32 bytes", -1);
  }
  return Buffer.from(key);
}

function check(rc: number, op: string): void {
  if (rc === OPE_OK) {
    return;
  }
  const msg = `${op} failed (${rc}): ${lastError()}`;
  if (rc === OPE_ERR_VERIFY) {
    throw new VerifyError(msg, rc);
  }
  throw new OpeError(msg, rc);
}

export function envelopeSign(secretKey: Uint8Array, envelope: string | object): string {
  const jsonIn = typeof envelope === "string" ? envelope : JSON.stringify(envelope);
  const ptr = ope_envelope_sign_alloc(keyBuffer(secretKey), jsonIn);
  if (!ptr) {
    throw new OpeError(`ope_envelope_sign_alloc: ${lastError()}`, -1);
  }
  try {
    return koffi.decode(ptr, "char", -1);
  } finally {
    ope_string_free(ptr);
  }
}

export function envelopeVerify(
  publicKey: Uint8Array,
  envelope: string | object,
  maxSkewSecs = 300,
): void {
  const json = typeof envelope === "string" ? envelope : JSON.stringify(envelope);
  const rc = ope_envelope_verify(keyBuffer(publicKey), json, maxSkewSecs);
  if (rc === OPE_ERR_VERIFY) {
    throw new VerifyError(`ope_envelope_verify: ${lastError()}`, rc);
  }
  check(rc, "ope_envelope_verify");
}

export function envelopeVerifyDev(envelope: string | object): void {
  const json = typeof envelope === "string" ? envelope : JSON.stringify(envelope);
  const rc = ope_envelope_verify_dev_json(json);
  if (rc === OPE_ERR_VERIFY) {
    throw new VerifyError(`ope_envelope_verify_dev_json: ${lastError()}`, rc);
  }
  check(rc, "ope_envelope_verify_dev_json");
}
