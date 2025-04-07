import csv from "csv-parser";
import express from "express";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { isRunning, startSniffing, stopSniffing } from "../utils/runPython.js";

const router = express.Router();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default () => {
   const RESULTS_FILE = path.join(__dirname, "../anomaly_results.csv");

   router.post("/start", (req, res) => {
      const result = startSniffing();
      res.json(result);
   });

   router.post("/stop", (req, res) => {
      const result = stopSniffing();
      res.json(result);
   });

   router.get("/results", (req, res) => {
      if (!fs.existsSync(RESULTS_FILE)) {
         return res.json({ total: 0, anomalies: 0, protocols: {}, data: [] });
      }

      let total = 0;
      let anomalies = 0;
      let protocols = {};
      let Data = [];

      fs.createReadStream(RESULTS_FILE)
         .pipe(csv())
         .on("data", (row) => {
            total++;
            if (row["bad_packet"] === "1") anomalies++;
            protocols[row["Protocol"]] = (protocols[row["Protocol"]] || 0) + 1;

            Data.push(row);
         })
         .on("end", () => {
            res.json({
               total_packets: total,
               anomalies,
               normal: total - anomalies,
               protocol_breakdown: protocols,
               recent: Data,
               running: isRunning(),
            });
         });
   });

   return router;
};
