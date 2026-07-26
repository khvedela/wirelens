import { pinnedRustEnvironment, run } from "./tooling.mjs";

const environment = pinnedRustEnvironment();
run(environment.CARGO, ["test", "--locked"], { env: environment });
