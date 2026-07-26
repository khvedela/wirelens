#!/usr/bin/env node

import {
  createTemporaryFixtureDirectory,
  DEFAULT_SUPPORTED_LARGE_TARGET_BYTES,
  generateBrowserIngestionFixtures,
} from "./capture-fixtures.mjs";

function parseInteger(value, name) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1)
    throw new Error(`${name} must be a positive integer`);
  return parsed;
}

function parseByteSize(value) {
  const match = /^(\d+)(B|KiB|MiB)?$/u.exec(value);
  if (match === null) throw new Error(`invalid byte size: ${value}`);
  const multiplier = match[2] === "MiB" ? 1024 * 1024 : match[2] === "KiB" ? 1024 : 1;
  return parseInteger(match[1], "byte size") * multiplier;
}

function usage() {
  return `Generate deterministic WireLens browser-ingestion fixtures in OS temporary storage.

Usage:
  node apps/web/tests/support/generate-capture-fixtures.mjs [options]

Options:
  --output PATH                    Empty directory below the OS temporary directory
  --medium-records N               Medium fixture records (default: 4096)
  --medium-payload-bytes N         Medium captured bytes per record (default: 240)
  --supported-large-target SIZE    Successful large target (default: 8MiB smoke size)
  --supported-large-payload SIZE   Captured bytes per large record (default: 1MiB)
  --skip-architecture-oversize     Omit the sparse >=500 MiB size-guard fixture
  --help                           Show this help

For qualifying near-cap evidence, pass --supported-large-target 240MiB explicitly.
The >=500 MiB fixture is sparse and tests pre-read rejection only.
`;
}

const options = {
  includeArchitectureOversize: true,
  mediumPayloadBytes: 240,
  mediumRecords: 4_096,
  outputDirectory: undefined,
  supportedLargePayloadBytes: 1024 * 1024,
  supportedLargeTargetBytes: DEFAULT_SUPPORTED_LARGE_TARGET_BYTES,
};

for (let index = 2; index < process.argv.length; index += 1) {
  const argument = process.argv[index];
  if (argument === "--help") {
    process.stdout.write(usage());
    process.exit(0);
  }
  if (argument === "--skip-architecture-oversize") {
    options.includeArchitectureOversize = false;
    continue;
  }
  const value = process.argv[index + 1];
  if (value === undefined) throw new Error(`${argument} requires a value`);
  index += 1;
  switch (argument) {
    case "--medium-payload-bytes":
      options.mediumPayloadBytes = parseInteger(value, argument);
      break;
    case "--medium-records":
      options.mediumRecords = parseInteger(value, argument);
      break;
    case "--output":
      options.outputDirectory = value;
      break;
    case "--supported-large-payload":
      options.supportedLargePayloadBytes = parseByteSize(value);
      break;
    case "--supported-large-target":
      options.supportedLargeTargetBytes = parseByteSize(value);
      break;
    default:
      throw new Error(`unknown argument: ${argument}\n\n${usage()}`);
  }
}

options.outputDirectory ??= await createTemporaryFixtureDirectory();
const result = await generateBrowserIngestionFixtures(options);
process.stdout.write(
  `${JSON.stringify(
    {
      fixtureCount: result.manifest.fixtures.length,
      outputDirectory: result.outputDirectory,
      supportedLargeTargetBytes: options.supportedLargeTargetBytes,
    },
    null,
    2,
  )}\n`,
);
