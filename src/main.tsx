import { createRoot } from "react-dom/client";
import App from "./App.tsx";
import "./index.css";
import { initializeEnv } from "./lib/safeEnv";

// SECURITY: Validate environment before rendering to catch credential misconfigurations early
initializeEnv();

createRoot(document.getElementById("root")!).render(<App />);
