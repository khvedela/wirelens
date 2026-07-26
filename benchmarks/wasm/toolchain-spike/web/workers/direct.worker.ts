import init, {
  byte_sum as byteSum,
  probe_schema_version as schemaVersion,
} from "../generated/direct/wirelens_wasm_probe.js";

import { installProbeWorker } from "./run-probe";

installProbeWorker("direct", {
  byteSum,
  init: async () => init(),
  schemaVersion,
});
