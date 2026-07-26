import { BoundaryClient } from "./boundary-client";
import {
  createOptionDensePcapng,
  createSyntheticPcap,
  createTruncatedPcap,
} from "./synthetic-pcap";

declare global {
  interface Window {
    wirelensBoundary: BoundaryClient;
    wirelensFixtures: {
      optionDensePcapng: typeof createOptionDensePcapng;
      synthetic: typeof createSyntheticPcap;
      truncated: typeof createTruncatedPcap;
    };
  }
}

const status = document.querySelector("#status");
if (!(status instanceof HTMLElement)) throw new Error("harness status element is missing");

const client = new BoundaryClient();
window.wirelensBoundary = client;
window.wirelensFixtures = {
  optionDensePcapng: createOptionDensePcapng,
  synthetic: createSyntheticPcap,
  truncated: createTruncatedPcap,
};

void client.metadata().then(
  (metadata) => {
    status.dataset.state = "ready";
    status.textContent = `Ready: API ${metadata.apiVersion}, batch ${metadata.batchSchemaVersion}`;
  },
  (error: unknown) => {
    status.dataset.state = "error";
    status.textContent = error instanceof Error ? error.message : "boundary worker failed";
  },
);
