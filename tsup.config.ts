import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.mts'],
  format: ['cjs', 'esm'],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  minify: true,
  treeshake: true
})
