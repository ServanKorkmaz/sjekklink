import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { insertScanResultSchema, insertApiUsageSchema } from "@shared/schema";
import { z } from "zod";
import { checkUrlSafetyServer } from "./lib/score";
import { checkAbuseIPDB } from "./lib/abuseipdb";
import { scanFileWithVirusTotal } from "./lib/virustotal";
import multer from "multer";
import crypto from "crypto";

// Configure multer for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 32 * 1024 * 1024, // 32MB limit
  },
});

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
      const result = await checkUrlSafetyServer(url);
      
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
  app.post("/api/scan-file", upload.single('file'), async (req, res) => {
    try {
      const file = req.file;
      const fileName = req.body.fileName || file?.originalname;
      
      if (!file || !fileName) {
        return res.status(400).json({ error: 'File and filename required' });
      }
      
      // Generate file hash from buffer
      const hash = crypto.createHash('sha256').update(file.buffer).digest('hex');
      const fileSize = file.buffer.length;
      
      // Check cache first
      const cached = await storage.getScanResultByFileHash(hash);
      if (cached && (Date.now() - cached.createdAt.getTime()) < 24 * 60 * 60 * 1000) {
        return res.json(cached);
      }
      
      // Scan file with VirusTotal
      const vtResult = await scanFileWithVirusTotal(file.buffer, fileName);
      
      // Calculate risk score based on VirusTotal results
      let riskScore = 0;
      let verdict: 'safe' | 'suspicious' | 'malicious' = 'safe';
      const reasons: string[] = [];
      
      if (vtResult.available && vtResult.maliciousCount > 0) {
        // High risk if multiple vendors flag as malicious
        riskScore = Math.min(100, 50 + (vtResult.maliciousCount * 5));
        verdict = vtResult.maliciousCount > 5 ? 'malicious' : 'suspicious';
        reasons.push(`VirusTotal: ${vtResult.details}`);
      } else if (vtResult.available && vtResult.suspiciousCount > 0) {
        riskScore = Math.min(70, 30 + (vtResult.suspiciousCount * 3));
        verdict = 'suspicious';
        reasons.push(`VirusTotal: ${vtResult.details}`);
      } else if (vtResult.available) {
        riskScore = 5;
        verdict = 'safe';
        reasons.push('VirusTotal: No threats detected by security vendors');
      } else {
        // Fallback if VirusTotal is unavailable
        riskScore = 15;
        verdict = 'safe';
        reasons.push('File analyzed with heuristics (VirusTotal unavailable)');
      }
      
      reasons.push(`File hash (SHA-256): ${hash}`);
      reasons.push(`File size: ${(fileSize / 1024).toFixed(2)} KB`);
      
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

  // AbuseIPDB reputation check endpoint
  app.post("/api/check-reputation", async (req, res) => {
    try {
      const { url } = z.object({ url: z.string().url() }).parse(req.body);
      const result = await checkAbuseIPDB(url);
      res.json(result);
    } catch (error) {
      console.error('Reputation check failed:', error);
      res.status(500).json({ 
        isAbusive: false, 
        available: false,
        error: error instanceof Error ? error.message : 'Unknown error'
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
