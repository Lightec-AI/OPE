import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  OPE_TRAFFIC_CLASS_API,
  OPE_TRAFFIC_CLASS_LIVE_CHAT,
  parseOpeTrafficClass,
  trafficClassHeaderMetaConsistent,
  ENGINE_PLANE_PATH_INFERENCE_RESULT,
  HEADER_OPE_DESIRED_POOL_TARGET,
} from "./types.js";
import { parseOpeStreamLine, isOpeStreamContentType, CONTENT_TYPE_OPE_JSON_STREAM } from "./stream.js";

describe("traffic class", () => {
  it("parses live_chat and api", () => {
    assert.equal(parseOpeTrafficClass("live_chat"), OPE_TRAFFIC_CLASS_LIVE_CHAT);
    assert.equal(parseOpeTrafficClass("API"), OPE_TRAFFIC_CLASS_API);
    assert.equal(parseOpeTrafficClass("other"), null);
  });

  it("requires header/meta agreement", () => {
    const ok = trafficClassHeaderMetaConsistent("live_chat", "live_chat");
    assert.equal(ok.ok, true);
    const bad = trafficClassHeaderMetaConsistent("live_chat", "api");
    assert.equal(bad.ok, false);
  });
});

describe("ope stream", () => {
  it("parses server_share and ciphertext frames", () => {
    const share = parseOpeStreamLine(
      JSON.stringify({ ope_stream: "1.0", server_share: "abc" }),
    );
    assert.deepEqual(share, { ope_stream: "1.0", server_share: "abc" });
    const chunk = parseOpeStreamLine(
      JSON.stringify({ ope_stream: "1.0", seq: 0, ciphertext: "x", final: true }),
    );
    assert.equal(chunk && "seq" in chunk && chunk.seq, 0);
  });

  it("detects stream content type", () => {
    assert.equal(isOpeStreamContentType(CONTENT_TYPE_OPE_JSON_STREAM), true);
    assert.equal(isOpeStreamContentType("application/json"), false);
  });
});

describe("engine plane paths", () => {
  it("exports inference result path", () => {
    assert.equal(ENGINE_PLANE_PATH_INFERENCE_RESULT, "/v1/ope/inference/result");
  });

  it("exports desired pool target header", () => {
    assert.equal(HEADER_OPE_DESIRED_POOL_TARGET, "x-ope-desired-pool-target");
  });
});
