import { type User, type UpsertUser, type ScanResult, type InsertScanResult, type ApiUsage, type InsertApiUsage, users, scanResults, apiUsage } from "@shared/schema";
import { randomUUID } from "crypto";
import { db } from "./db";
import { eq, desc, and } from "drizzle-orm";

export interface IStorage {
  // User operations (required for Replit Auth)
  getUser(id: string): Promise<User | undefined>;
  upsertUser(user: UpsertUser): Promise<User>;
  
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

export class DatabaseStorage implements IStorage {
  constructor() {}

  async getUser(id: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user || undefined;
  }

  async upsertUser(userData: UpsertUser): Promise<User> {
    const [user] = await db
      .insert(users)
      .values(userData)
      .onConflictDoUpdate({
        target: users.id,
        set: {
          ...userData,
          updatedAt: new Date(),
        },
      })
      .returning();
    return user;
  }

  async getScanResult(id: string): Promise<ScanResult | undefined> {
    const [result] = await db.select().from(scanResults).where(eq(scanResults.id, id));
    return result || undefined;
  }

  async getScanResultByUrl(url: string): Promise<ScanResult | undefined> {
    const [result] = await db.select().from(scanResults)
      .where(and(
        eq(scanResults.url, url),
        eq(scanResults.scanType, 'url')
      ));
    return result || undefined;
  }

  async getScanResultByFileHash(hash: string): Promise<ScanResult | undefined> {
    const [result] = await db.select().from(scanResults)
      .where(and(
        eq(scanResults.fileHash, hash),
        eq(scanResults.scanType, 'file')
      ));
    return result || undefined;
  }

  async createScanResult(insertResult: InsertScanResult): Promise<ScanResult> {
    const [result] = await db.insert(scanResults).values(insertResult).returning();
    return result;
  }

  async getRecentScans(limit: number = 100): Promise<ScanResult[]> {
    const results = await db.select().from(scanResults)
      .orderBy(desc(scanResults.createdAt))
      .limit(limit);
    return results;
  }

  async recordApiUsage(insertUsage: InsertApiUsage): Promise<ApiUsage> {
    const [usage] = await db.insert(apiUsage).values(insertUsage).returning();
    return usage;
  }

  async getApiUsageStats(): Promise<{
    totalScans: number;
    maliciousCount: number;
    errorRate: number;
    activeUsers: number;
  }> {
    const scans = await db.select().from(scanResults);
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

export const storage = new DatabaseStorage();
