// Server-side URL scoring with direct provider integration
import { checkGoogleSafeBrowsing } from '../../client/src/lib/providers/gsb';
import { checkAbuseIPDB } from './abuseipdb';
import { getWhoisData } from '../../client/src/lib/providers/whois';
import { analyzeUrlHeuristics, analyzeDomainAge } from '../../client/src/lib/providers/heuristics';
import { submitToUrlScan } from '../../client/src/lib/providers/urlscan';
import type { SecurityCheck, DomainInfo } from '../../client/src/lib/types';

export async function checkUrlSafetyServer(url: string): Promise<{
  riskScore: number;
  verdict: 'safe' | 'suspicious' | 'malicious';
  reasons: string[];
  metadata: Record<string, any>;
  securityChecks: SecurityCheck[];
  domainInfo?: DomainInfo;
}> {
  const reasons: string[] = [];
  const securityChecks: SecurityCheck[] = [];
  let totalScore = 0;
  const metadata: Record<string, any> = {};

  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;

    // Track external API availability
    let gsbWorking = false;
    let abuseIpDbWorking = false;
    
    // Google Safe Browsing check
    try {
      const gsbResult = await checkGoogleSafeBrowsing(url);
      gsbWorking = true; // If no error thrown, GSB is working
      if (!gsbResult.isSafe) {
        totalScore += 60;
        reasons.push(`Flagged by Google Safe Browsing: ${gsbResult.threatType}`);
        securityChecks.push({
          name: 'Google Safe Browsing',
          status: 'malicious',
          details: gsbResult.threatType || 'Threat detected'
        });
      } else {
        securityChecks.push({
          name: 'Google Safe Browsing',
          status: 'clean',
          details: 'No threats detected'
        });
      }
    } catch (error) {
      securityChecks.push({
        name: 'Google Safe Browsing',
        status: 'error',
        details: 'Service unavailable'
      });
    }

    // AbuseIPDB reputation check (server-side)
    try {
      const abuseResult = await checkAbuseIPDB(url);
      abuseIpDbWorking = abuseResult.available;
      
      if (abuseResult.isAbusive) {
        totalScore += 60;
        reasons.push(`Flagged by IP reputation service: ${abuseResult.details}`);
        securityChecks.push({
          name: 'IP Reputation',
          status: 'malicious',
          details: abuseResult.details || 'Abusive IP detected'
        });
      } else if (abuseResult.available) {
        securityChecks.push({
          name: 'IP Reputation',
          status: 'clean',
          details: 'Clean IP reputation'
        });
      } else {
        securityChecks.push({
          name: 'IP Reputation',
          status: 'error',
          details: 'Service unavailable - API key missing or service down'
        });
      }
    } catch (error) {
      securityChecks.push({
        name: 'IP Reputation',
        status: 'error',
        details: 'Service unavailable - network error'
      });
    }
    
    const externalApiWorking = gsbWorking || abuseIpDbWorking;

    // WHOIS and domain age analysis
    let domainInfo: DomainInfo | undefined;
    try {
      const whoisData = await getWhoisData(domain);
      const ageAnalysis = analyzeDomainAge(whoisData.age);
      
      totalScore += ageAnalysis.score;
      if (ageAnalysis.flag) {
        reasons.push(ageAnalysis.flag);
      }

      domainInfo = {
        registrar: whoisData.registrar || 'Unknown',
        ip: '0.0.0.0', // Would need IP lookup service
        country: 'Unknown', // Would need GeoIP service
        age: whoisData.age || 0
      };

      securityChecks.push({
        name: 'Domain Age',
        status: ageAnalysis.score > 20 ? 'suspicious' : 'clean',
        details: whoisData.age ? `${whoisData.age} days old` : 'Unknown age'
      });
    } catch (error) {
      securityChecks.push({
        name: 'Domain Age',
        status: 'error',
        details: 'WHOIS lookup failed'
      });
    }

    // Enhanced heuristic analysis (more weight if external APIs unavailable)
    const heuristicResult = analyzeUrlHeuristics(url);
    const heuristicWeight = externalApiWorking ? 1.0 : 1.4;
    const adjustedHeuristicScore = Math.round(heuristicResult.score * heuristicWeight);
    totalScore += adjustedHeuristicScore;
    reasons.push(...heuristicResult.flags);
    
    if (!externalApiWorking && heuristicResult.flags.length > 0) {
      reasons.push('Enhanced heuristic analysis applied due to external service limitations');
    }

    if (heuristicResult.flags.length > 0) {
      securityChecks.push({
        name: 'Heuristic Analysis',
        status: adjustedHeuristicScore > 30 ? 'suspicious' : 'clean',
        details: `${heuristicResult.flags.length} suspicious patterns detected${!externalApiWorking ? ' (enhanced weighting applied)' : ''}`
      });
    } else {
      securityChecks.push({
        name: 'Heuristic Analysis',
        status: 'clean',
        details: 'No suspicious patterns found'
      });
    }

    // Submit to URLScan.io for background analysis
    try {
      const urlscanResult = await submitToUrlScan(url);
      if (urlscanResult.uuid) {
        metadata.urlscanUuid = urlscanResult.uuid;
      }
    } catch (error) {
      console.warn('URLScan.io submission failed:', error);
    }

    // Determine verdict
    let verdict: 'safe' | 'suspicious' | 'malicious';
    if (totalScore >= 70) {
      verdict = 'malicious';
    } else if (totalScore >= 30) {
      verdict = 'suspicious';
    } else {
      verdict = 'safe';
    }

    // Add summary reason
    if (reasons.length === 0) {
      reasons.push('No security threats detected');
    }

    return {
      riskScore: Math.min(totalScore, 100),
      verdict,
      reasons,
      metadata,
      securityChecks,
      domainInfo
    };

  } catch (error) {
    console.error('URL safety check failed:', error);
    return {
      riskScore: 50,
      verdict: 'suspicious',
      reasons: ['URL analysis failed'],
      metadata: { error: error instanceof Error ? error.message : 'Unknown error' },
      securityChecks: [{
        name: 'URL Analysis',
        status: 'error',
        details: 'Analysis failed'
      }]
    };
  }
}