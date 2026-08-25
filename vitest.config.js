import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node', // Ensure tests run in Node.js environment
    setupFiles: [], // No specific setup file needed for now
    globals: true, // Make Vitest APIs globally available
  },
});