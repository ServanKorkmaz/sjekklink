import crypto from 'crypto';

const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const VT_API_BASE = 'https://www.virustotal.com/api/v3';

interface VTUrlScanResponse {
  data: {
    id: string;
    type: string;
  };
}

interface VTAnalysisResponse {
  data: {
    attributes: {
      status: string;
      stats: {
        malicious: number;
        suspicious: number;
        undetected: number;
        harmless: number;
        timeout: number;
      };
      results?: Record<string, {
        category: string;
        result: string;
        method: string;
        engine_name: string;
      }>;
    };
  };
}

interface VTFileScanResponse {
  data: {
    id: string;
    type: string;
  };
}

/**
 * Scan a URL with VirusTotal
 */
export async function scanUrlWithVirusTotal(url: string): Promise<{
  isSafe: boolean;
  maliciousCount: number;
  suspiciousCount: number;
  details: string;
  available: boolean;
}> {
  if (!VT_API_KEY) {
    return {
      isSafe: true,
      maliciousCount: 0,
      suspiciousCount: 0,
      details: 'API key not configured',
      available: false
    };
  }

  try {
    // Submit URL for scanning
    const formData = new URLSearchParams();
    formData.append('url', url);

    const submitResponse = await fetch(`${VT_API_BASE}/urls`, {
      method: 'POST',
      headers: {
        'x-apikey': VT_API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: formData.toString()
    });

    if (!submitResponse.ok) {
      throw new Error(`VirusTotal API error: ${submitResponse.status}`);
    }

    const submitData: VTUrlScanResponse = await submitResponse.json();
    const analysisId = submitData.data.id;

    // Wait a bit for analysis to complete (VirusTotal usually has cached results)
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Get analysis results
    const analysisResponse = await fetch(`${VT_API_BASE}/analyses/${analysisId}`, {
      headers: {
        'x-apikey': VT_API_KEY
      }
    });

    if (!analysisResponse.ok) {
      throw new Error(`VirusTotal analysis error: ${analysisResponse.status}`);
    }

    const analysisData: VTAnalysisResponse = await analysisResponse.json();
    const stats = analysisData.data.attributes.stats;

    const maliciousCount = stats.malicious || 0;
    const suspiciousCount = stats.suspicious || 0;
    const isSafe = maliciousCount === 0 && suspiciousCount === 0;

    let details = 'No threats detected';
    if (maliciousCount > 0) {
      details = `${maliciousCount} security vendors flagged this URL as malicious`;
    } else if (suspiciousCount > 0) {
      details = `${suspiciousCount} security vendors flagged this URL as suspicious`;
    }

    return {
      isSafe,
      maliciousCount,
      suspiciousCount,
      details,
      available: true
    };
  } catch (error) {
    console.error('VirusTotal URL scan error:', error);
    return {
      isSafe: true,
      maliciousCount: 0,
      suspiciousCount: 0,
      details: error instanceof Error ? error.message : 'Service unavailable',
      available: false
    };
  }
}

/**
 * Scan a file with VirusTotal using file hash
 */
export async function scanFileWithVirusTotal(fileBuffer: Buffer, fileName: string): Promise<{
  isSafe: boolean;
  maliciousCount: number;
  suspiciousCount: number;
  details: string;
  available: boolean;
  fileHash: string;
}> {
  if (!VT_API_KEY) {
    const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
    return {
      isSafe: true,
      maliciousCount: 0,
      suspiciousCount: 0,
      details: 'API key not configured',
      available: false,
      fileHash: hash
    };
  }

  try {
    // Calculate file hash
    const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

    // First, check if we already have results for this file hash
    try {
      const hashCheckResponse = await fetch(`${VT_API_BASE}/files/${hash}`, {
        headers: {
          'x-apikey': VT_API_KEY
        }
      });

      if (hashCheckResponse.ok) {
        const hashData: VTAnalysisResponse = await hashCheckResponse.json();
        const stats = hashData.data.attributes.stats;

        const maliciousCount = stats.malicious || 0;
        const suspiciousCount = stats.suspicious || 0;
        const isSafe = maliciousCount === 0 && suspiciousCount === 0;

        let details = 'No threats detected';
        if (maliciousCount > 0) {
          details = `${maliciousCount}/${Object.keys(hashData.data.attributes.results || {}).length} security vendors flagged this file as malicious`;
        } else if (suspiciousCount > 0) {
          details = `${suspiciousCount}/${Object.keys(hashData.data.attributes.results || {}).length} security vendors flagged this file as suspicious`;
        }

        return {
          isSafe,
          maliciousCount,
          suspiciousCount,
          details,
          available: true,
          fileHash: hash
        };
      }
    } catch (hashCheckError) {
      // File not in database, continue with upload
      console.log('File not in VirusTotal database, uploading...');
    }

    // Upload file for scanning (only if not found in hash check)
    const FormData = (await import('form-data')).default;
    const formData = new FormData();
    formData.append('file', fileBuffer, { filename: fileName });

    const uploadResponse = await fetch(`${VT_API_BASE}/files`, {
      method: 'POST',
      headers: {
        'x-apikey': VT_API_KEY,
        ...formData.getHeaders()
      },
      body: formData as any
    });

    if (!uploadResponse.ok) {
      throw new Error(`VirusTotal upload error: ${uploadResponse.status}`);
    }

    const uploadData: VTFileScanResponse = await uploadResponse.json();
    const analysisId = uploadData.data.id;

    // Wait for analysis to complete (longer for file analysis)
    await new Promise(resolve => setTimeout(resolve, 5000));

    // Get analysis results
    const analysisResponse = await fetch(`${VT_API_BASE}/analyses/${analysisId}`, {
      headers: {
        'x-apikey': VT_API_KEY
      }
    });

    if (!analysisResponse.ok) {
      throw new Error(`VirusTotal analysis error: ${analysisResponse.status}`);
    }

    const analysisData: VTAnalysisResponse = await analysisResponse.json();
    const stats = analysisData.data.attributes.stats;

    const maliciousCount = stats.malicious || 0;
    const suspiciousCount = stats.suspicious || 0;
    const isSafe = maliciousCount === 0 && suspiciousCount === 0;

    let details = 'No threats detected';
    if (maliciousCount > 0) {
      details = `${maliciousCount} security vendors flagged this file as malicious`;
    } else if (suspiciousCount > 0) {
      details = `${suspiciousCount} security vendors flagged this file as suspicious`;
    }

    return {
      isSafe,
      maliciousCount,
      suspiciousCount,
      details,
      available: true,
      fileHash: hash
    };
  } catch (error) {
    console.error('VirusTotal file scan error:', error);
    const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
    return {
      isSafe: true,
      maliciousCount: 0,
      suspiciousCount: 0,
      details: error instanceof Error ? error.message : 'Service unavailable',
      available: false,
      fileHash: hash
    };
  }
}
