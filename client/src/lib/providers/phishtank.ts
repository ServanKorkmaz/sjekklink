// PhishTank integration
export async function checkPhishTank(url: string): Promise<{
  isPhishing: boolean;
  details?: string;
}> {
  const apiKey = process.env.PHISHTANK_API_KEY || '';
  
  try {
    const encodedUrl = encodeURIComponent(url);
    const response = await fetch(`https://checkurl.phishtank.com/checkurl/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `url=${encodedUrl}&format=json${apiKey ? `&app_key=${apiKey}` : ''}`,
    });

    const data = await response.json();
    
    if (data.results && data.results.in_database) {
      return {
        isPhishing: data.results.valid,
        details: data.results.verified ? 'Verified phishing site' : 'Reported phishing site',
      };
    }

    return { isPhishing: false };
  } catch (error) {
    console.error('PhishTank check failed:', error);
    return { isPhishing: false }; // Fail open
  }
}
