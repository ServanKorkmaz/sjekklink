import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { insertScanResultSchema, insertApiUsageSchema } from "@shared/schema";
import { z } from "zod";
import { checkUrlSafety } from "../client/src/lib/score";
import crypto from "crypto";

// Rate limiting store
const rateLimitStore = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT = 10; // requests per minute
const RATE_WINDOW = 60 * 1000; // 1 minute

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const userLimit = rateLimitStore.get(ip);
  
  if (!userLimit || now > userLimit.resetTime) {
    rateLimitStore.set(ip, { count: 1, resetTime: now + RATE_WINDOW });
    return true;
  }
  
  if (userLimit.count >= RATE_LIMIT) {
    return false;
  }
  
  userLimit.count++;
  return true;
}

export async function registerRoutes(app: Express): Promise<Server> {
  // Rate limiting middleware
  app.use('/api/', (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    
    if (!checkRateLimit(ip)) {
      return res.status(429).json({ 
        error: 'Rate limit exceeded. Maximum 10 requests per minute.' 
      });
    }
    
    // Record API usage
    storage.recordApiUsage({
      endpoint: req.path,
      ipAddress: ip,
      userAgent: req.get('User-Agent') || '',
      requestCount: 1
    });
    
    next();
  });

  // URL Check endpoint
  app.post("/api/check-url", async (req, res) => {
    try {
      const { url } = z.object({ url: z.string().url() }).parse(req.body);
      
      // Check cache first
      const cached = await storage.getScanResultByUrl(url);
      if (cached && (Date.now() - cached.createdAt.getTime()) < 24 * 60 * 60 * 1000) {
        return res.json(cached);
      }
      
      // Perform URL safety check
      const result = await checkUrlSafety(url);
      
      // Store result
      const scanResult = await storage.createScanResult({
        url,
        fileHash: null,
        fileName: null,
        fileSize: null,
        scanType: 'url',
        riskScore: result.riskScore,
        verdict: result.verdict,
        reasons: result.reasons,
        metadata: result.metadata
      });
      
      res.json(scanResult);
    } catch (error) {
      console.error('URL check error:', error);
      res.status(400).json({ 
        error: error instanceof Error ? error.message : 'Invalid request' 
      });
    }
  });

  // File Scan endpoint
  app.post("/api/scan-file", async (req, res) => {
    try {
      const { fileBuffer, fileName } = req.body;
      
      if (!fileBuffer || !fileName) {
        return res.status(400).json({ error: 'File buffer and name required' });
      }
      
      // Generate file hash
      const hash = crypto.createHash('sha256').update(Buffer.from(fileBuffer, 'base64')).digest('hex');
      const fileSize = Buffer.from(fileBuffer, 'base64').length;
      
      // Check cache first
      const cached = await storage.getScanResultByFileHash(hash);
      if (cached && (Date.now() - cached.createdAt.getTime()) < 24 * 60 * 60 * 1000) {
        return res.json(cached);
      }
      
      // Mock file scanning (in real implementation, integrate with VirusTotal)
      const riskScore = Math.floor(Math.random() * 100);
      const verdict = riskScore < 30 ? 'safe' : riskScore < 70 ? 'suspicious' : 'malicious';
      const reasons = [
        `File hash: ${hash}`,
        `File size: ${fileSize} bytes`,
        verdict === 'malicious' ? 'Multiple security vendors flagged this file' : 'No threats detected'
      ];
      
      // Store result
      const scanResult = await storage.createScanResult({
        url: null,
        fileHash: hash,
        fileName,
        fileSize,
        scanType: 'file',
        riskScore,
        verdict,
        reasons,
        metadata: { hash, originalName: fileName }
      });
      
      res.json(scanResult);
    } catch (error) {
      console.error('File scan error:', error);
      res.status(400).json({ 
        error: error instanceof Error ? error.message : 'File scan failed' 
      });
    }
  });

  // Admin endpoints
  app.get("/api/admin/stats", async (req, res) => {
    try {
      const stats = await storage.getApiUsageStats();
      res.json(stats);
    } catch (error) {
      console.error('Stats error:', error);
      res.status(500).json({ error: 'Failed to fetch stats' });
    }
  });

  app.get("/api/admin/recent-scans", async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 100;
      const scans = await storage.getRecentScans(limit);
      res.json(scans);
    } catch (error) {
      console.error('Recent scans error:', error);
      res.status(500).json({ error: 'Failed to fetch recent scans' });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
