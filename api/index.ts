import express from "express";
import type { Express } from "express";
import { registerRoutes } from "../server/routes";

let app: Express | null = null;
let initialized = false;

async function init() {
  if (initialized) return;
  app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));
  // Register all API routes/middleware onto this Express instance
  await registerRoutes(app);
  initialized = true;
}

export default async function handler(req: any, res: any) {
  await init();
  return (app as any)(req, res);
}


