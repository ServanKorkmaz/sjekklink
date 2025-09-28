// WHOIS data provider
export async function getWhoisData(domain: string): Promise<{
  registrar?: string;
  creationDate?: Date;
  expirationDate?: Date;
  age?: number;
}> {
  try {
    // Using a public WHOIS API service
    const response = await fetch(`https://api.whoisfreaks.com/v1.0/whois?apiKey=${process.env.WHOIS_API_KEY || ''}&whois=live&domainName=${domain}`);
    
    if (!response.ok) {
      return {};
    }

    const data = await response.json();
    
    const creationDate = data.create_date ? new Date(data.create_date) : undefined;
    const expirationDate = data.expire_date ? new Date(data.expire_date) : undefined;
    const age = creationDate ? Math.floor((Date.now() - creationDate.getTime()) / (1000 * 60 * 60 * 24)) : undefined;

    return {
      registrar: data.registrar_name,
      creationDate,
      expirationDate,
      age,
    };
  } catch (error) {
    console.error('WHOIS lookup failed:', error);
    return {};
  }
}
