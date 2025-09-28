import { type User, type InsertUser, type ScanResult, type InsertScanResult, type ApiUsage, type InsertApiUsage } from "@shared/schema";
import { randomUUID } from "crypto";

export interface IStorage {
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  
  getScanResult(id: string): Promise<ScanResult | undefined>;
  getScanResultByUrl(url: string): Promise<ScanResult | undefined>;
  getScanResultByFileHash(hash: string): Promise<ScanResult | undefined>;
  createScanResult(result: InsertScanResult): Promise<ScanResult>;
  getRecentScans(limit?: number): Promise<ScanResult[]>;
  
  recordApiUsage(usage: InsertApiUsage): Promise<ApiUsage>;
  getApiUsageStats(): Promise<{
    totalScans: number;
    maliciousCount: number;
    errorRate: number;
    activeUsers: number;
  }>;
}

export class MemStorage implements IStorage {
  private users: Map<string, User>;
  private scanResults: Map<string, ScanResult>;
  private apiUsage: Map<string, ApiUsage>;

  constructor() {
    this.users = new Map();
    this.scanResults = new Map();
    this.apiUsage = new Map();
  }

  async getUser(id: string): Promise<User | undefined> {
    return this.users.get(id);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(
      (user) => user.username === username,
    );
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = randomUUID();
    const user: User = { ...insertUser, id };
    this.users.set(id, user);
    return user;
  }

  async getScanResult(id: string): Promise<ScanResult | undefined> {
    return this.scanResults.get(id);
  }

  async getScanResultByUrl(url: string): Promise<ScanResult | undefined> {
    return Array.from(this.scanResults.values()).find(
      (result) => result.url === url && result.scanType === 'url'
    );
  }

  async getScanResultByFileHash(hash: string): Promise<ScanResult | undefined> {
    return Array.from(this.scanResults.values()).find(
      (result) => result.fileHash === hash && result.scanType === 'file'
    );
  }

  async createScanResult(insertResult: InsertScanResult): Promise<ScanResult> {
    const id = randomUUID();
    const now = new Date();
    const result: ScanResult = { 
      ...insertResult, 
      id, 
      createdAt: now,
      updatedAt: now,
      metadata: insertResult.metadata || null
    };
    this.scanResults.set(id, result);
    return result;
  }

  async getRecentScans(limit: number = 100): Promise<ScanResult[]> {
    return Array.from(this.scanResults.values())
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .slice(0, limit);
  }

  async recordApiUsage(insertUsage: InsertApiUsage): Promise<ApiUsage> {
    const id = randomUUID();
    const usage: ApiUsage = { 
      ...insertUsage, 
      id, 
      createdAt: new Date(),
      ipAddress: insertUsage.ipAddress || null,
      userAgent: insertUsage.userAgent || null,
      requestCount: insertUsage.requestCount || 1
    };
    this.apiUsage.set(id, usage);
    return usage;
  }

  async getApiUsageStats(): Promise<{
    totalScans: number;
    maliciousCount: number;
    errorRate: number;
    activeUsers: number;
  }> {
    const scans = Array.from(this.scanResults.values());
    const totalScans = scans.length;
    const maliciousCount = scans.filter(s => s.verdict === 'malicious').length;
    
    return {
      totalScans,
      maliciousCount,
      errorRate: 2.1, // Mock value
      activeUsers: 1423 // Mock value
    };
  }
}

export const storage = new MemStorage();
