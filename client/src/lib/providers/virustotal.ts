// VirusTotal integration
export async function checkVirusTotal(fileHash: string): Promise<{
  malicious: number;
  suspicious: number;
  clean: number;
  vendors: Array<{
    name: string;
    result: string;
    category: string;
  }>;
}> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY || '';
  
  if (!apiKey) {
    console.warn('VirusTotal API key not configured');
    return { malicious: 0, suspicious: 0, clean: 0, vendors: [] };
  }

  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/files/${fileHash}`, {
      headers: {
        'X-Apikey': apiKey,
      },
    });

    if (response.status === 404) {
      return { malicious: 0, suspicious: 0, clean: 0, vendors: [] };
    }

    const data = await response.json();
    const stats = data.data.attributes.last_analysis_stats;
    const results = data.data.attributes.last_analysis_results;
    
    const vendors = Object.entries(results).map(([name, result]: [string, any]) => ({
      name,
      result: result.result || 'Clean',
      category: result.category || 'clean',
    }));

    return {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      clean: stats.harmless || 0,
      vendors,
    };
  } catch (error) {
    console.error('VirusTotal check failed:', error);
    return { malicious: 0, suspicious: 0, clean: 0, vendors: [] };
  }
}
