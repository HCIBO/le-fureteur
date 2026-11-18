import { defineConfig, Plugin } from "vite";
import react from "@vitejs/plugin-react";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

function depsManifest(): Plugin {
  return {
    name: "scakit-deps-manifest",
    apply: "build",
    writeBundle(opts) {
      const lock = JSON.parse(readFileSync(resolve(__dirname, "package-lock.json"), "utf8"));
      const pkg = JSON.parse(readFileSync(resolve(__dirname, "package.json"), "utf8"));
      const direct = new Set(Object.keys(pkg.dependencies ?? {}));
      const packages = Object.entries<any>(lock.packages ?? {})
        .filter(([path, p]) => path.startsWith("node_modules/") && !p.dev && p.version)
        .map(([path, p]) => {
          const name = path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
          return { name, version: p.version, direct: direct.has(name) && !path.includes("/node_modules/", 1) };
        });
      const out = resolve(opts.dir ?? "dist", "deps.json");
      writeFileSync(out, JSON.stringify({ built_at: new Date().toISOString(), packages }, null, 1));
    },
  };
}

export default defineConfig({
  plugins: [react(), depsManifest()],
  server: { port: 5173, proxy: { "/api": "http://127.0.0.1:8800" } },
  build: { outDir: "dist", sourcemap: false },
});
