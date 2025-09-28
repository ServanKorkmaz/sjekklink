// Heuristic analysis functions
export function analyzeUrlHeuristics(url: string): {
  score: number;
  flags: string[];
} {
  const flags: string[] = [];
  let score = 0;

  try {
    const urlObj = new URL(url);
    
    // Check for IP address instead of domain
    if (/^\d+\.\d+\.\d+\.\d+/.test(urlObj.hostname)) {
      score += 30;
      flags.push('Uses IP address instead of domain name');
    }
    
    // Check URL length
    if (url.length > 200) {
      score += 20;
      flags.push('Unusually long URL');
    }
    
    // Check for @ symbol in URL
    if (url.includes('@')) {
      score += 25;
      flags.push('Contains @ symbol (potential redirect)');
    }
    
    // Check number of subdomains
    const subdomains = urlObj.hostname.split('.').length - 2;
    if (subdomains > 3) {
      score += 15;
      flags.push('Excessive number of subdomains');
    }
    
    // Check for suspicious characters
    if (/[^\w\-\.\/\?\=\&\%\#\+]/.test(url)) {
      score += 10;
      flags.push('Contains suspicious characters');
    }
    
    // Check protocol
    if (urlObj.protocol !== 'https:') {
      score += 15;
      flags.push('Not using HTTPS');
    }
    
    // Check for known suspicious TLDs
    const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download', '.top', '.bid', '.loan', '.win', '.racing'];
    if (suspiciousTlds.some(tld => urlObj.hostname.endsWith(tld))) {
      score += 25;
      flags.push('Uses suspicious top-level domain');
    }
    
    // Check for suspicious keywords in domain
    const suspiciousKeywords = ['secure', 'verify', 'account', 'update', 'confirm', 'suspended', 'locked', 'urgent'];
    const domainLower = urlObj.hostname.toLowerCase();
    if (suspiciousKeywords.some(keyword => domainLower.includes(keyword))) {
      score += 15;
      flags.push('Domain contains suspicious security-related keywords');
    }
    
    // Check for homograph attacks (mixed character sets)
    if (/[а-я]/.test(urlObj.hostname) || /[α-ω]/.test(urlObj.hostname)) {
      score += 20;
      flags.push('Domain uses non-Latin characters (potential homograph attack)');
    }
    
    // Check for excessive hyphens or numbers
    const hyphenCount = (urlObj.hostname.match(/-/g) || []).length;
    const numberCount = (urlObj.hostname.match(/\d/g) || []).length;
    if (hyphenCount > 3) {
      score += 10;
      flags.push('Domain contains excessive hyphens');
    }
    if (numberCount > 4) {
      score += 10;
      flags.push('Domain contains excessive numbers');
    }
    
    // Check for URL shorteners
    const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'short.link'];
    if (shorteners.some(shortener => urlObj.hostname.includes(shortener))) {
      score += 15;
      flags.push('URL shortener detected - cannot verify final destination');
    }
    
    // Check path for suspicious patterns
    const path = urlObj.pathname + urlObj.search;
    if (/(\.exe|\.zip|\.rar|\.bat|\.cmd|\.scr)$/i.test(path)) {
      score += 30;
      flags.push('URL leads to executable file download');
    }
    
    if (/password|login|signin|account/.test(path.toLowerCase())) {
      // This could be legitimate, so lower score
      score += 5;
      flags.push('URL contains login/password related path');
    }
    
  } catch (error) {
    score += 50;
    flags.push('Invalid URL format');
  }
  
  return { score: Math.min(score, 100), flags };
}

export function analyzeDomainAge(ageInDays?: number): {
  score: number;
  flag?: string;
} {
  if (!ageInDays) {
    return { score: 0 };
  }
  
  if (ageInDays < 30) {
    return { score: 40, flag: 'Domain registered less than 30 days ago' };
  } else if (ageInDays < 90) {
    return { score: 25, flag: 'Domain registered less than 90 days ago' };
  } else if (ageInDays < 365) {
    return { score: 10, flag: 'Domain registered less than 1 year ago' };
  }
  
  return { score: 0 };
}
