import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ALL_FIXTURES } from "./fixtures.js";

const dir = join(process.cwd(), "data", "fixtures");
mkdirSync(dir, { recursive: true });
for (const [name, factory] of Object.entries(ALL_FIXTURES)) {
  writeFileSync(join(dir, name), factory());
  console.log("written", name, factory().length, "bytes");
}
