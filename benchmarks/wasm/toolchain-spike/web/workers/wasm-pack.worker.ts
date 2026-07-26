import init, {
  byte_sum as byteSum,
  probe_schema_version as schemaVersion,
} from "../generated/wasm-pack/wirelens_wasm_probe.js";

import { installProbeWorker } from "./run-probe";

installProbeWorker("wasm-pack", {
  byteSum,
  init: async () => init(),
  schemaVersion,
});
