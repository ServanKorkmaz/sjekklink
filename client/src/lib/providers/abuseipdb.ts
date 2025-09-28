// Client-side API call to server's AbuseIPDB endpoint
export async function checkAbuseIPDB(url: string): Promise<{
  isAbusive: boolean;
  confidencePercentage?: number;
  details?: string;
  available: boolean;
}> {
  try {
    const response = await fetch('/api/check-reputation', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      throw new Error(`Server error: ${response.status}`);
    }

    const data = await response.json();
    return {
      isAbusive: data.isAbusive || false,
      confidencePercentage: data.confidencePercentage,
      details: data.details,
      available: data.available !== false // Default to true if not specified
    };
  } catch (error) {
    console.error('AbuseIPDB check failed:', error);
    return { 
      isAbusive: false, 
      available: false 
    };
  }
}