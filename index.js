import express from "express";
import cors from "cors";
import anomalyRoutes from "./routes/anomaly.js";

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

app.use("/api", anomalyRoutes());

app.listen(PORT, () => {
   console.log(`🚀 Server running at http://localhost:${PORT}`);
});
