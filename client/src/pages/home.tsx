import { useState } from "react";
import { Header } from "@/components/header";
import { Footer } from "@/components/footer";
import { UrlScanner } from "@/components/url-scanner";
import { FileScanner } from "@/components/file-scanner";
import { ResultsModal } from "@/components/results-modal";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { FileText, Link as LinkIcon } from "lucide-react";
import { nb } from "@/lib/i18n/nb";
import type { ScanResult } from "@/lib/types";

export default function Home() {
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [activeTab, setActiveTab] = useState("url");

  const handleScanResult = (result: ScanResult) => {
    setScanResult(result);
  };

  const handleCloseResults = () => {
    setScanResult(null);
  };

  return (
    <div className="min-h-screen bg-slate-900 text-white">
      <Header />
      <main className="py-16">
        <div className="container mx-auto px-4">
          <div className="max-w-4xl mx-auto text-center">
            {/* Logo and Title */}
            <div className="mb-8">
              <div className="flex items-center justify-center mb-4">
                <div className="w-16 h-16 bg-blue-500 rounded-lg flex items-center justify-center mr-4">
                  <span className="text-2xl font-bold text-white">T</span>
                </div>
                <h1 className="text-4xl font-bold text-blue-400">{nb.appName.toUpperCase()}</h1>
              </div>
              <p className="text-lg text-slate-300 max-w-2xl mx-auto">
                {nb.main.subtitle}
              </p>
            </div>

            {/* Tab Interface */}
            <Card className="bg-slate-800 border-slate-700 shadow-2xl">
              <CardContent className="p-8">
                <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
                  <TabsList className="grid w-full grid-cols-2 bg-slate-700 mb-8">
                    <TabsTrigger 
                      value="file" 
                      className="data-[state=active]:bg-blue-500 data-[state=active]:text-white text-slate-300 font-semibold py-3"
                      data-testid="tab-file"
                    >
                      <FileText className="w-4 h-4 mr-2" />
                      {nb.main.fileTab}
                    </TabsTrigger>
                    <TabsTrigger 
                      value="url" 
                      className="data-[state=active]:bg-blue-500 data-[state=active]:text-white text-slate-300 font-semibold py-3"
                      data-testid="tab-url"
                    >
                      <LinkIcon className="w-4 h-4 mr-2" />
                      {nb.main.urlTab}
                    </TabsTrigger>
                  </TabsList>
                  
                  <TabsContent value="file" className="space-y-6">
                    <FileScanner onResult={handleScanResult} />
                  </TabsContent>
                  
                  <TabsContent value="url" className="space-y-6">
                    <UrlScanner onResult={handleScanResult} />
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>

            {/* Footer Disclaimer */}
            <div className="mt-8 text-sm text-slate-400 max-w-3xl mx-auto">
              <p>
                {nb.footer.disclaimer}
                <Button variant="link" className="text-blue-400 p-0 ml-1 h-auto">
                  {nb.footer.learnMore}
                </Button>
              </p>
            </div>
          </div>
        </div>
        {scanResult && (
          <ResultsModal result={scanResult} onClose={handleCloseResults} />
        )}
      </main>
    </div>
  );
}
