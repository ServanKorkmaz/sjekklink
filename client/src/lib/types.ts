export interface SecurityCheck {
  name: string;
  status: 'clean' | 'suspicious' | 'malicious' | 'error';
  details: string;
}

export interface DomainInfo {
  registrar: string;
  ip: string;
  country: string;
  age: number;
}

export interface ScanResult {
  id: string;
  url?: string;
  fileName?: string;
  fileSize?: number;
  scanType: 'url' | 'file';
  riskScore: number;
  verdict: 'safe' | 'suspicious' | 'malicious';
  reasons: string[];
  metadata?: Record<string, any>;
  securityChecks?: SecurityCheck[];
  domainInfo?: DomainInfo;
  createdAt: Date;
}

export interface FileUploadResult {
  success: boolean;
  scanResult?: ScanResult;
  error?: string;
}
