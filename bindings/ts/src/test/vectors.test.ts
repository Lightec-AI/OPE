import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  envelopeSign,
  envelopeVerify,
  envelopeVerifyDev,
  version,
} from "../index.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");
const vectorPath = path.join(root, "spec/vectors/001-valid-plaintext.json");

type Vector = {
  signing_key_seed_hex: string;
  verifying_key_hex: string;
  envelope: Record<string, unknown>;
};

const vector = JSON.parse(fs.readFileSync(vectorPath, "utf8")) as Vector;

test("version", () => {
  assert.equal(version(), "0.1.0");
});

test("vector 001 dev verify", () => {
  envelopeVerifyDev(vector.envelope);
});

test("sign verify roundtrip", () => {
  const unsigned = { ...vector.envelope };
  delete unsigned.sig;
  unsigned.payload_hash = "";
  unsigned.ts = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const secret = Buffer.from(vector.signing_key_seed_hex, "hex");
  const publicKey = Buffer.from(vector.verifying_key_hex, "hex");
  const signed = envelopeSign(secret, unsigned);
  envelopeVerify(publicKey, signed, 600);
});
