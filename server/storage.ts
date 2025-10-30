import { type User, type UpsertUser, type ScanResult, type InsertScanResult, type ApiUsage, type InsertApiUsage, users, scanResults, apiUsage } from "@shared/schema";
import { randomUUID } from "crypto";
import { eq, desc, and } from "drizzle-orm";
// Lazily import db only when DATABASE_URL is present to allow dev fallback
let db: any;
if (process.env.DATABASE_URL) {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  db = require("./db").db;
}

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

class InMemoryStorage implements IStorage {
  private users: Record<string, User> = {};
  private scans: Record<string, ScanResult> = {};
  private apiUsage: ApiUsage[] = [];

  async getUser(id: string): Promise<User | undefined> {
    return this.users[id];
  }

  async upsertUser(userData: UpsertUser): Promise<User> {
    const existing = this.users[userData.id!];
    const user: User = {
      id: userData.id || randomUUID(),
      email: userData.email ?? null as any,
      firstName: userData.firstName ?? null as any,
      lastName: userData.lastName ?? null as any,
      profileImageUrl: userData.profileImageUrl ?? null as any,
      createdAt: existing?.createdAt || new Date(),
      updatedAt: new Date(),
    } as unknown as User;
    this.users[user.id] = user;
    return user;
  }

  async getScanResult(id: string): Promise<ScanResult | undefined> {
    return this.scans[id];
  }

  async getScanResultByUrl(url: string): Promise<ScanResult | undefined> {
    return Object.values(this.scans).find((s) => s.url === url && s.scanType === 'url');
  }

  async getScanResultByFileHash(hash: string): Promise<ScanResult | undefined> {
    return Object.values(this.scans).find((s) => s.fileHash === hash && s.scanType === 'file');
  }

  async createScanResult(insertResult: InsertScanResult): Promise<ScanResult> {
    const id = randomUUID();
    const result: ScanResult = {
      id,
      url: insertResult.url ?? null as any,
      fileHash: insertResult.fileHash ?? null as any,
      fileName: insertResult.fileName ?? null as any,
      fileSize: insertResult.fileSize ?? null as any,
      scanType: insertResult.scanType as any,
      riskScore: insertResult.riskScore,
      verdict: insertResult.verdict as any,
      reasons: insertResult.reasons,
      metadata: insertResult.metadata ?? null as any,
      createdAt: new Date(),
      updatedAt: new Date(),
    } as unknown as ScanResult;
    this.scans[id] = result;
    return result;
  }

  async getRecentScans(limit: number = 100): Promise<ScanResult[]> {
    return Object.values(this.scans)
      .sort((a, b) => (b.createdAt as any as number) - (a.createdAt as any as number))
      .slice(0, limit);
  }

  async recordApiUsage(insertUsage: InsertApiUsage): Promise<ApiUsage> {
    const usage: ApiUsage = {
      id: randomUUID(),
      endpoint: insertUsage.endpoint,
      ipAddress: insertUsage.ipAddress ?? null as any,
      userAgent: insertUsage.userAgent ?? null as any,
      requestCount: insertUsage.requestCount ?? 1,
      createdAt: new Date(),
    } as unknown as ApiUsage;
    this.apiUsage.push(usage);
    return usage;
  }

  async getApiUsageStats(): Promise<{ totalScans: number; maliciousCount: number; errorRate: number; activeUsers: number; }> {
    const scans = Object.values(this.scans);
    const totalScans = scans.length;
    const maliciousCount = scans.filter((s) => s.verdict === 'malicious').length;
    return { totalScans, maliciousCount, errorRate: 0, activeUsers: Object.keys(this.users).length };
  }
}

export const storage: IStorage = process.env.DATABASE_URL ? new DatabaseStorage() : new InMemoryStorage();
