import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

let processRef = null;

// ESM-compatible __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function startSniffing() {
   if (processRef) return { running: true };

   const scriptPath = path.join(__dirname, "../model/live_sniff.py");
   processRef = spawn("python", [scriptPath]);

   processRef.stdout.on("data", (data) => {
      console.log(`[Python]: ${data}`);
   });

   processRef.stderr.on("data", (data) => {
      console.error(`[Python Error]: ${data}`);
   });

   processRef.on("close", (code) => {
      console.log(`Python script exited with code ${code}`);
      processRef = null;
   });

   return { started: true };
}

export function isRunning() {
   return processRef !== null;
}

export function stopSniffing() {
   if (processRef) {
      processRef.kill("SIGINT");
      processRef = null;
      return { stopped: true };
   }
   return { running: false };
}
