import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const outputDirectory = resolve(process.argv[2] ?? "fixtures");
mkdirSync(outputDirectory, { recursive: true });

function uint16(value) {
  const bytes = Buffer.alloc(2);
  bytes.writeUInt16LE(value);
  return bytes;
}

function uint32(value) {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(value >>> 0);
  return bytes;
}

function uint16be(value) {
  const bytes = Buffer.alloc(2);
  bytes.writeUInt16BE(value);
  return bytes;
}

function uint32be(value) {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value >>> 0);
  return bytes;
}

function legacyPcap(packetCount) {
  const header = Buffer.concat([
    Buffer.from([0xd4, 0xc3, 0xb2, 0xa1]), uint16(2), uint16(4), uint32(0),
    uint32(0), uint32(65_535), uint32(1),
  ]);
  const payload = Buffer.alloc(60, 0x42);
  const packets = Array.from({ length: packetCount }, (_, index) => Buffer.concat([
    uint32(index), uint32(0), uint32(payload.length), uint32(payload.length), payload,
  ]));
  return Buffer.concat([header, ...packets]);
}

function bigEndianLegacyPcap() {
  const payload = Buffer.alloc(60, 0x42);
  return Buffer.concat([
    Buffer.from([0xa1, 0xb2, 0xc3, 0xd4]), uint16be(2), uint16be(4), uint32be(0),
    uint32be(0), uint32be(65_535), uint32be(1), uint32be(1), uint32be(0),
    uint32be(payload.length), uint32be(payload.length), payload,
  ]);
}

function block(type, body) {
  const length = 12 + body.length;
  return Buffer.concat([uint32(type), uint32(length), body, uint32(length)]);
}

function pcapng(packetCount) {
  const sectionHeader = Buffer.concat([
    uint32(0x0a0d0d0a), uint32(28), Buffer.from([0x4d, 0x3c, 0x2b, 0x1a]),
    uint16(1), uint16(0), Buffer.alloc(8, 0xff), uint32(28),
  ]);
  const interfaceDescription = block(1, Buffer.concat([uint16(1), uint16(0), uint32(65_535)]));
  const payload = Buffer.alloc(60, 0x42);
  const packets = Array.from({ length: packetCount }, (_, index) => block(6, Buffer.concat([
    uint32(0), uint32(0), uint32(index), uint32(payload.length), uint32(payload.length), payload,
  ])));
  return Buffer.concat([sectionHeader, interfaceDescription, ...packets]);
}

function multiInterfacePcapng() {
  const capture = pcapng(0);
  const secondInterface = block(1, Buffer.concat([uint16(1), uint16(0), uint32(65_535)]));
  const payload = Buffer.alloc(60, 0x42);
  const packetOnSecondInterface = block(6, Buffer.concat([
    uint32(1), uint32(0), uint32(1), uint32(payload.length), uint32(payload.length), payload,
  ]));
  return Buffer.concat([capture, secondInterface, packetOnSecondInterface]);
}

const smallPcap = legacyPcap(100);
const mediumPcap = legacyPcap(50_000);
const smallPcapng = pcapng(100);
const mediumPcapng = pcapng(50_000);

writeFileSync(resolve(outputDirectory, "small.pcap"), smallPcap);
writeFileSync(resolve(outputDirectory, "medium.pcap"), mediumPcap);
writeFileSync(resolve(outputDirectory, "small.pcapng"), smallPcapng);
writeFileSync(resolve(outputDirectory, "medium.pcapng"), mediumPcapng);
writeFileSync(resolve(outputDirectory, "truncated.pcap"), smallPcap.subarray(0, 60));
writeFileSync(resolve(outputDirectory, "truncated.pcapng"), smallPcapng.subarray(0, 78));
writeFileSync(resolve(outputDirectory, "big_endian.pcap"), bigEndianLegacyPcap());
writeFileSync(resolve(outputDirectory, "multi_interface.pcapng"), multiInterfacePcapng());
