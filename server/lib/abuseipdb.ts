// Server-side AbuseIPDB integration for IP and domain reputation checking
export async function checkAbuseIPDB(url: string): Promise<{
  isAbusive: boolean;
  confidencePercentage?: number;
  details?: string;
  available: boolean;
}> {
  const apiKey = process.env.ABUSEIPDB_API_KEY || '';
  
  if (!apiKey) {
    return { isAbusive: false, available: false };
  }

  try {
    // Extract domain from URL
    const urlObj = new URL(url);
    const domain = urlObj.hostname;

    // First try to resolve domain to IP
    let ipAddress = domain;
    try {
      const dnsResponse = await fetch(`https://dns.google/resolve?name=${domain}&type=A`);
      if (dnsResponse.ok) {
        const dnsData = await dnsResponse.json();
        if (dnsData.Answer && dnsData.Answer.length > 0) {
          ipAddress = dnsData.Answer[0].data;
        }
      }
    } catch (e) {
      // If DNS lookup fails, continue with domain name
    }

    // Check domain/IP reputation
    const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ipAddress)}&maxAgeInDays=90&verbose`, {
      method: 'GET',
      headers: {
        'Key': apiKey,
        'Accept': 'application/json',
      }
    });

    if (!response.ok) {
      throw new Error(`AbuseIPDB API error: ${response.status}`);
    }

    const data = await response.json();
    
    if (data.data && data.data.abuseConfidencePercentage > 25) {
      return {
        isAbusive: true,
        confidencePercentage: data.data.abuseConfidencePercentage,
        details: `Abuse confidence: ${data.data.abuseConfidencePercentage}%`,
        available: true
      };
    }

    return { 
      isAbusive: false, 
      confidencePercentage: data.data?.abuseConfidencePercentage || 0,
      available: true
    };
  } catch (error) {
    console.error('AbuseIPDB check failed:', error);
    return { isAbusive: false, available: false };
  }
}