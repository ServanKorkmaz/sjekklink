// AbuseIPDB integration for IP and domain reputation checking
export async function checkAbuseIPDB(url: string): Promise<{
  isAbusive: boolean;
  confidencePercentage?: number;
  details?: string;
}> {
  const apiKey = process.env.ABUSEIPDB_API_KEY || '';
  
  if (!apiKey) {
    console.warn('AbuseIPDB API key not configured');
    return { isAbusive: false };
  }

  try {
    // Extract domain from URL
    const urlObj = new URL(url);
    const domain = urlObj.hostname;

    // Check domain reputation
    const response = await fetch('https://api.abuseipdb.com/api/v2/check', {
      method: 'GET',
      headers: {
        'Key': apiKey,
        'Accept': 'application/json',
      },
      body: new URLSearchParams({
        ipAddress: domain,
        maxAgeInDays: '90',
        verbose: ''
      })
    });

    if (!response.ok) {
      throw new Error(`AbuseIPDB API error: ${response.status}`);
    }

    const data = await response.json();
    
    if (data.data && data.data.abuseConfidencePercentage > 25) {
      return {
        isAbusive: true,
        confidencePercentage: data.data.abuseConfidencePercentage,
        details: `Abuse confidence: ${data.data.abuseConfidencePercentage}%`
      };
    }

    return { 
      isAbusive: false, 
      confidencePercentage: data.data?.abuseConfidencePercentage || 0 
    };
  } catch (error) {
    console.error('AbuseIPDB check failed:', error);
    return { isAbusive: false }; // Fail open
  }
}