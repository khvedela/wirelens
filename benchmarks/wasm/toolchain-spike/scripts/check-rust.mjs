import { pinnedRustEnvironment, run } from "./tooling.mjs";

const environment = pinnedRustEnvironment();
run(environment.CARGO, ["fmt", "--all", "--", "--check"], { env: environment });
run(
  environment.CARGO,
  ["clippy", "--locked", "--all-targets", "--", "-D", "warnings"],
  { env: environment },
);
