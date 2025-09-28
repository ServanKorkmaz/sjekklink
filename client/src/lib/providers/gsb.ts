// Google Safe Browsing integration
export async function checkGoogleSafeBrowsing(url: string): Promise<{
  isSafe: boolean;
  threatType?: string;
}> {
  const apiKey = process.env.GSB_API_KEY || '';
  
  if (!apiKey) {
    console.warn('Google Safe Browsing API key not configured');
    return { isSafe: true };
  }

  try {
    const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        client: {
          clientId: 'trygglink',
          clientVersion: '1.0.0',
        },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      }),
    });

    const data = await response.json();
    
    if (data.matches && data.matches.length > 0) {
      return {
        isSafe: false,
        threatType: data.matches[0].threatType,
      };
    }

    return { isSafe: true };
  } catch (error) {
    console.error('Google Safe Browsing check failed:', error);
    return { isSafe: true }; // Fail open
  }
}
