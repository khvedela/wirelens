import assert from "node:assert/strict";
import { readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  ADR_0001_LARGE_CAPTURE_MINIMUM_BYTES,
  createHostileFixtureBytes,
  createTemporaryFixtureDirectory,
  describeFixtureStorage,
  encodePcapGlobalHeader,
  encodePcapngSectionHeader,
  generateBrowserIngestionFixtures,
  identifyCaptureMagic,
  PCAP_VARIANTS,
  writeSparseArchitectureOversizePcap,
  writeSupportedLargePcap,
} from "./capture-fixtures.mjs";

async function temporaryDirectory(t, prefix) {
  const directory = await createTemporaryFixtureDirectory(prefix);
  t.after(async () => rm(directory, { force: true, recursive: true }));
  return directory;
}

test("emits and recognizes every legacy PCAP magic", () => {
  assert.equal(PCAP_VARIANTS.length, 4);
  const seen = new Set();
  for (const variant of PCAP_VARIANTS) {
    const bytes = encodePcapGlobalHeader(variant.id);
    assert.deepEqual(Array.from(bytes.subarray(0, 4)), Array.from(variant.magic));
    assert.deepEqual(identifyCaptureMagic(bytes), {
      endian: variant.endian,
      format: "pcap",
      fractionResolution: variant.fractionResolution,
      variant: variant.id,
    });
    seen.add(Array.from(variant.magic).join("-"));
  }
  assert.equal(seen.size, 4);
});

test("emits both PCAPNG byte-order magics", () => {
  const little = encodePcapngSectionHeader("little");
  const big = encodePcapngSectionHeader("big");
  assert.deepEqual(Array.from(little.subarray(0, 4)), [0x0a, 0x0d, 0x0d, 0x0a]);
  assert.deepEqual(Array.from(little.subarray(8, 12)), [0x4d, 0x3c, 0x2b, 0x1a]);
  assert.deepEqual(Array.from(big.subarray(8, 12)), [0x1a, 0x2b, 0x3c, 0x4d]);
  assert.deepEqual(identifyCaptureMagic(little), { endian: "little", format: "pcapng" });
  assert.deepEqual(identifyCaptureMagic(big), { endian: "big", format: "pcapng" });
});

test("hostile byte fixtures cover short, random, truncated, malformed, and bounded bombs", () => {
  const fixtures = createHostileFixtureBytes();
  const names = Object.keys(fixtures);
  for (const required of [
    "empty.capture",
    "short-pcap-magic.pcap",
    "random-magic.capture",
    "truncated-pcap-header.pcap",
    "truncated-pcap-record.pcap",
    "truncated-pcapng-section.pcapng",
    "malformed-pcapng-bom.pcapng",
    "malformed-pcapng-footer.pcapng",
    "oversized-declared-pcap-record.pcap",
    "oversized-declared-pcapng-block.pcapng",
    "option-dense-pcapng.pcapng",
    "dense-packet-admission.pcap",
  ]) {
    assert(names.includes(required), `${required} is present`);
  }
  assert.deepEqual(identifyCaptureMagic(fixtures["empty.capture"]), { format: "short" });
  assert.deepEqual(identifyCaptureMagic(fixtures["random-magic.capture"]), {
    format: "unsupported",
  });
});

test("streams a supported fixture in bounded writes", async (t) => {
  const directory = await temporaryDirectory(t, "wirelens-supported-writer-");
  const targetBytes = 2 * 1024 * 1024;
  const result = await writeSupportedLargePcap(join(directory, "supported.pcap"), {
    maxChunkBytes: 256 * 1024,
    payloadBytes: 64 * 1024,
    targetBytes,
  });
  const storage = await describeFixtureStorage(join(directory, "supported.pcap"));
  assert.equal(storage.sizeBytes, result.byteLength);
  assert(result.byteLength <= targetBytes);
  assert(result.byteLength > targetBytes - 64 * 1024 - 16);
  assert(result.largestWriteBytes <= 256 * 1024 + 64 * 1024);
  assert.match(result.sha256, /^[0-9a-f]{64}$/u);
});

test("creates the >=500 MiB architecture guard as a sparse logical file", async (t) => {
  const directory = await temporaryDirectory(t, "wirelens-sparse-guard-");
  const fixturePath = join(directory, "oversize.pcap");
  const result = await writeSparseArchitectureOversizePcap(fixturePath);
  const storage = await describeFixtureStorage(fixturePath);
  assert(storage.sizeBytes >= ADR_0001_LARGE_CAPTURE_MINIMUM_BYTES);
  assert.equal(result.sha256, null);
  assert.equal(result.largestWriteBytes, 24);
  if (storage.allocatedBytes !== undefined) {
    assert(
      storage.allocatedBytes < 1024 * 1024,
      `sparse fixture allocated ${storage.allocatedBytes} physical bytes`,
    );
  }
});

test("generates a deterministic smoke set and provenance manifest in temporary storage", async (t) => {
  const directory = await temporaryDirectory(t, "wirelens-fixture-set-");
  const secondDirectory = await temporaryDirectory(t, "wirelens-fixture-set-repeat-");
  const options = {
    includeArchitectureOversize: true,
    mediumPayloadBytes: 240,
    mediumRecords: 16,
    supportedLargePayloadBytes: 64 * 1024,
    supportedLargeTargetBytes: 1024 * 1024,
  };
  const { manifest } = await generateBrowserIngestionFixtures({
    ...options,
    outputDirectory: directory,
  });
  const repeated = await generateBrowserIngestionFixtures({
    ...options,
    outputDirectory: secondDirectory,
  });
  assert.deepEqual(repeated.manifest, manifest);
  assert.equal(manifest.provenance.containsObservedTraffic, false);
  assert.equal(
    manifest.fixtures.filter(({ fileName }) => fileName.startsWith("small-pcap-")).length,
    4,
  );
  assert.equal(
    manifest.fixtures.filter(({ fileName }) => fileName.startsWith("small-pcapng-")).length,
    2,
  );
  assert(manifest.fixtures.some(({ fileName }) => fileName === "medium.pcap"));
  assert(manifest.fixtures.some(({ fileName }) => fileName === "medium.pcapng"));
  assert(manifest.fixtures.some(({ fileName }) => fileName === "packet-inspector.pcap"));
  assert(manifest.fixtures.some(({ fileName }) => fileName === "supported-large.pcap"));
  assert(manifest.fixtures.some(({ fileName }) => fileName === "adr-0001-oversize-guard.pcap"));
  const persisted = JSON.parse(await readFile(join(directory, "fixture-manifest.json"), "utf8"));
  assert.deepEqual(persisted, manifest);
  for (const fixture of manifest.fixtures) {
    assert.match(fixture.recipeSha256, /^[0-9a-f]{64}$/u);
    if (fixture.storage === "materialized") assert.match(fixture.sha256, /^[0-9a-f]{64}$/u);
  }
});
