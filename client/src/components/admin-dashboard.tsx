import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { 
  Search, 
  AlertTriangle, 
  Users, 
  CircleAlert, 
  Download, 
  RefreshCw,
  ArrowUp,
  ArrowDown
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { nb as nbLocale } from "date-fns/locale";
import { nb } from "@/lib/i18n/nb";
import type { ScanResult } from "@/lib/types";

export function AdminDashboard() {
  const { data: stats, refetch: refetchStats } = useQuery({
    queryKey: ['/api/admin/stats'],
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const { data: recentScans, refetch: refetchScans } = useQuery<ScanResult[]>({
    queryKey: ['/api/admin/recent-scans'],
    refetchInterval: 30000,
  });

  const handleRefresh = () => {
    refetchStats();
    refetchScans();
  };

  const getVerdictBadge = (verdict: string) => {
    switch (verdict) {
      case 'safe':
        return <Badge variant="default" className="bg-green-100 text-green-800">{nb.status.clean}</Badge>;
      case 'suspicious':
        return <Badge variant="secondary" className="bg-yellow-100 text-yellow-800">{nb.status.suspicious}</Badge>;
      case 'malicious':
        return <Badge variant="destructive">{nb.status.malicious}</Badge>;
      default:
        return <Badge variant="outline">{verdict}</Badge>;
    }
  };

  const formatTimeAgo = (date: Date | string) => {
    const dateObj = typeof date === 'string' ? new Date(date) : date;
    return formatDistanceToNow(dateObj, { addSuffix: true, locale: nbLocale });
  };

  return (
    <section className="py-20 bg-background" data-testid="admin-dashboard">
      <div className="container mx-auto px-4">
        <div className="max-w-7xl mx-auto">
          <div className="flex items-center justify-between mb-8">
            <div>
              <h2 className="text-3xl font-bold text-foreground">{nb.admin.title}</h2>
              <p className="text-muted-foreground mt-2">{nb.admin.description}</p>
            </div>
            <div className="flex items-center space-x-4">
              <Button variant="outline" data-testid="button-export">
                <Download className="mr-2 h-4 w-4" />
                {nb.admin.exportData}
              </Button>
              <Button onClick={handleRefresh} data-testid="button-refresh">
                <RefreshCw className="mr-2 h-4 w-4" />
                {nb.admin.refresh}
              </Button>
            </div>
          </div>

          {/* Stats Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <Card>
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">{nb.admin.stats.totalScans}</p>
                    <p className="text-2xl font-bold text-foreground" data-testid="stat-total-scans">
                      {(stats as any)?.totalScans?.toLocaleString() || '0'}
                    </p>
                  </div>
                  <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center">
                    <Search className="text-primary text-xl" />
                  </div>
                </div>
                <p className="text-xs text-green-600 mt-2">
                  <ArrowUp className="inline h-3 w-3 mr-1" />
                  {nb.trends.increaseArrow}12% {nb.trends.fromLastWeek}
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">{nb.admin.stats.maliciousDetected}</p>
                    <p className="text-2xl font-bold text-foreground" data-testid="stat-malicious-count">
                      {(stats as any)?.maliciousCount?.toLocaleString() || '0'}
                    </p>
                  </div>
                  <div className="w-12 h-12 bg-destructive/10 rounded-lg flex items-center justify-center">
                    <AlertTriangle className="text-destructive text-xl" />
                  </div>
                </div>
                <p className="text-xs text-destructive mt-2">
                  <ArrowUp className="inline h-3 w-3 mr-1" />
                  {nb.trends.increaseArrow}3% {nb.trends.fromLastWeek}
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">{nb.admin.stats.errorRate}</p>
                    <p className="text-2xl font-bold text-foreground" data-testid="stat-error-rate">
                      {(stats as any)?.errorRate?.toFixed(1) || '0.0'}%
                    </p>
                  </div>
                  <div className="w-12 h-12 bg-yellow-100 rounded-lg flex items-center justify-center">
                    <CircleAlert className="text-yellow-600 text-xl" />
                  </div>
                </div>
                <p className="text-xs text-green-600 mt-2">
                  <ArrowDown className="inline h-3 w-3 mr-1" />
                  {nb.trends.decreaseArrow}0.4% {nb.trends.fromLastWeek}
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">{nb.admin.stats.activeUsers}</p>
                    <p className="text-2xl font-bold text-foreground" data-testid="stat-active-users">
                      {(stats as any)?.activeUsers?.toLocaleString() || '0'}
                    </p>
                  </div>
                  <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center">
                    <Users className="text-green-600 text-xl" />
                  </div>
                </div>
                <p className="text-xs text-green-600 mt-2">
                  <ArrowUp className="inline h-3 w-3 mr-1" />
                  {nb.trends.increaseArrow}8% {nb.trends.fromLastWeek}
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Recent Scans Table */}
          <Card>
            <CardHeader>
              <CardTitle>{nb.admin.recentScans}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Tidsstempel</TableHead>
                      <TableHead>URL/Fil</TableHead>
                      <TableHead>{nb.common.type}</TableHead>
                      <TableHead>{nb.common.result}</TableHead>
                      <TableHead>{nb.common.score}</TableHead>
                      <TableHead>{nb.common.action}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {recentScans?.map((scan) => (
                      <TableRow 
                        key={scan.id} 
                        className="hover:bg-muted/50 transition-colors"
                        data-testid={`scan-row-${scan.id}`}
                      >
                        <TableCell className="text-sm text-muted-foreground">
                          {formatTimeAgo(scan.createdAt)}
                        </TableCell>
                        <TableCell className="font-mono text-sm max-w-xs truncate">
                          {scan.url || scan.fileName}
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground capitalize">
                          {scan.scanType}
                        </TableCell>
                        <TableCell>
                          {getVerdictBadge(scan.verdict)}
                        </TableCell>
                        <TableCell className="font-medium">
                          {scan.riskScore}
                        </TableCell>
                        <TableCell>
                          <Button 
                            variant="ghost" 
                            size="sm"
                            data-testid={`button-view-details-${scan.id}`}
                          >
                            {nb.admin.viewDetails}
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                    {(!recentScans || recentScans.length === 0) && (
                      <TableRow>
                        <TableCell colSpan={6} className="text-center text-muted-foreground py-8">
                          {nb.errors.noRecentScans}
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </section>
  );
}
