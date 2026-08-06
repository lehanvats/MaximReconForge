import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    // Match FRONTEND_ORIGIN in the backend .env so CORS + cookies line up.
    port: 3000,
    host: true,
  },
});
