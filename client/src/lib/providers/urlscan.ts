// URLScan.io integration
export async function submitToUrlScan(url: string): Promise<{
  uuid?: string;
  message?: string;
}> {
  const apiKey = process.env.URLSCAN_API_KEY || '';
  
  if (!apiKey) {
    console.warn('URLScan.io API key not configured');
    return {};
  }

  try {
    const response = await fetch('https://urlscan.io/api/v1/scan/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'API-Key': apiKey,
      },
      body: JSON.stringify({
        url,
        visibility: 'private',
      }),
    });

    const data = await response.json();
    return data;
  } catch (error) {
    console.error('URLScan.io submission failed:', error);
    return {};
  }
}

export async function getUrlScanResult(uuid: string): Promise<{
  screenshot?: string;
  page?: any;
  verdicts?: any;
}> {
  try {
    const response = await fetch(`https://urlscan.io/api/v1/result/${uuid}/`);
    
    if (response.status === 404) {
      return {}; // Scan not ready yet
    }

    const data = await response.json();
    return data;
  } catch (error) {
    console.error('URLScan.io result fetch failed:', error);
    return {};
  }
}
