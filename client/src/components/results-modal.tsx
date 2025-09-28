import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { 
  Shield, 
  CheckCircle, 
  AlertTriangle, 
  XCircle, 
  ExternalLink, 
  Flag, 
  X,
  ListChecks,
  Info
} from "lucide-react";
import type { ScanResult } from "@/lib/types";

interface ResultsModalProps {
  result: ScanResult;
  onClose: () => void;
}

export function ResultsModal({ result, onClose }: ResultsModalProps) {
  const getVerdictColor = (verdict: string) => {
    switch (verdict) {
      case 'safe':
        return 'from-green-500 to-green-600';
      case 'suspicious':
        return 'from-yellow-500 to-yellow-600';
      case 'malicious':
        return 'from-red-500 to-red-600';
      default:
        return 'from-gray-500 to-gray-600';
    }
  };

  const getVerdictIcon = (verdict: string) => {
    switch (verdict) {
      case 'safe':
        return <Shield className="text-3xl" />;
      case 'suspicious':
        return <AlertTriangle className="text-3xl" />;
      case 'malicious':
        return <XCircle className="text-3xl" />;
      default:
        return <Shield className="text-3xl" />;
    }
  };

  const getCheckIcon = (status: string) => {
    switch (status) {
      case 'clean':
        return <CheckCircle className="text-green-500 h-5 w-5" />;
      case 'suspicious':
        return <AlertTriangle className="text-yellow-500 h-5 w-5" />;
      case 'malicious':
        return <XCircle className="text-red-500 h-5 w-5" />;
      case 'error':
        return <XCircle className="text-gray-500 h-5 w-5" />;
      default:
        return <CheckCircle className="text-green-500 h-5 w-5" />;
    }
  };

  const getCheckBadgeVariant = (status: string) => {
    switch (status) {
      case 'clean':
        return 'default';
      case 'suspicious':
        return 'secondary';
      case 'malicious':
        return 'destructive';
      case 'error':
        return 'outline';
      default:
        return 'default';
    }
  };

  return (
    <section className="py-16 bg-background" data-testid="results-modal">
      <div className="container mx-auto px-4">
        <div className="max-w-4xl mx-auto">
          <Card className="shadow-xl border border-border overflow-hidden">
            {/* Results Header */}
            <CardHeader className={`bg-gradient-to-r ${getVerdictColor(result.verdict)} text-white p-6`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-4">
                  <div className="w-16 h-16 bg-white/20 rounded-full flex items-center justify-center">
                    {getVerdictIcon(result.verdict)}
                  </div>
                  <div>
                    <h2 className="text-2xl font-bold capitalize" data-testid="text-verdict">
                      {result.verdict}
                    </h2>
                    <p className="text-white/90 break-all" data-testid="text-scanned-url">
                      {result.url || result.fileName}
                    </p>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-3xl font-bold" data-testid="text-risk-score">
                    {result.riskScore}
                  </div>
                  <div className="text-sm text-white/90">Risk Score</div>
                </div>
              </div>
            </CardHeader>

            {/* Detailed Results */}
            <CardContent className="p-6">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                {/* Security Checks */}
                <div>
                  <h3 className="text-lg font-semibold mb-4 flex items-center">
                    <ListChecks className="text-primary mr-2 h-5 w-5" />
                    Security Checks
                  </h3>
                  <div className="space-y-3">
                    {result.securityChecks?.map((check, index) => (
                      <div 
                        key={index} 
                        className="flex items-center justify-between p-3 bg-muted rounded-lg"
                        data-testid={`security-check-${index}`}
                      >
                        <div className="flex items-center space-x-3">
                          {getCheckIcon(check.status)}
                          <span className="font-medium">{check.name}</span>
                        </div>
                        <Badge variant={getCheckBadgeVariant(check.status)}>
                          {check.details}
                        </Badge>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Additional Info */}
                <div>
                  <h3 className="text-lg font-semibold mb-4 flex items-center">
                    <Info className="text-primary mr-2 h-5 w-5" />
                    {result.scanType === 'url' ? 'Domain Information' : 'File Information'}
                  </h3>
                  <div className="space-y-4">
                    {result.domainInfo && (
                      <>
                        <div className="p-4 bg-muted rounded-lg">
                          <div className="text-sm text-muted-foreground mb-1">Registrar</div>
                          <div className="font-medium" data-testid="text-registrar">
                            {result.domainInfo.registrar}
                          </div>
                        </div>
                        <div className="p-4 bg-muted rounded-lg">
                          <div className="text-sm text-muted-foreground mb-1">IP Address</div>
                          <div className="font-medium font-mono" data-testid="text-ip">
                            {result.domainInfo.ip}
                          </div>
                        </div>
                        <div className="p-4 bg-muted rounded-lg">
                          <div className="text-sm text-muted-foreground mb-1">Country</div>
                          <div className="font-medium" data-testid="text-country">
                            {result.domainInfo.country}
                          </div>
                        </div>
                      </>
                    )}
                    {result.scanType === 'file' && (
                      <>
                        <div className="p-4 bg-muted rounded-lg">
                          <div className="text-sm text-muted-foreground mb-1">File Size</div>
                          <div className="font-medium" data-testid="text-file-size">
                            {result.fileSize ? `${(result.fileSize / 1024 / 1024).toFixed(2)} MB` : 'Unknown'}
                          </div>
                        </div>
                        <div className="p-4 bg-muted rounded-lg">
                          <div className="text-sm text-muted-foreground mb-1">File Hash</div>
                          <div className="font-medium font-mono text-xs break-all" data-testid="text-file-hash">
                            {result.metadata?.hash || 'Unknown'}
                          </div>
                        </div>
                      </>
                    )}
                  </div>
                </div>
              </div>

              {/* Reasons */}
              {result.reasons.length > 0 && (
                <div className="mt-8">
                  <h3 className="text-lg font-semibold mb-4">Analysis Details</h3>
                  <ul className="space-y-2">
                    {result.reasons.map((reason, index) => (
                      <li 
                        key={index} 
                        className="flex items-start space-x-2 text-sm"
                        data-testid={`reason-${index}`}
                      >
                        <span className="text-muted-foreground">•</span>
                        <span>{reason}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Action Buttons */}
              <div className="flex flex-col sm:flex-row gap-4 mt-8 pt-6 border-t border-border">
                {result.url && (
                  <Button 
                    className="flex-1" 
                    onClick={() => window.open(result.url, '_blank')}
                    data-testid="button-visit-site"
                  >
                    <ExternalLink className="mr-2 h-4 w-4" />
                    Visit Site
                  </Button>
                )}
                <Button 
                  variant="secondary" 
                  className="flex-1"
                  data-testid="button-report-false-positive"
                >
                  <Flag className="mr-2 h-4 w-4" />
                  Report False Positive
                </Button>
                <Button 
                  variant="outline" 
                  onClick={onClose}
                  data-testid="button-close"
                >
                  <X className="mr-2 h-4 w-4" />
                  Close
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Disclaimer */}
          <Alert className="mt-6 border-amber-200 bg-amber-50">
            <AlertTriangle className="h-4 w-4 text-amber-600" />
            <AlertDescription className="text-amber-800">
              <strong>Disclaimer:</strong> TryggLink provides an indication only. Not legal proof. If you suspect fraud, contact your bank/police.
            </AlertDescription>
          </Alert>
        </div>
      </div>
    </section>
  );
}
