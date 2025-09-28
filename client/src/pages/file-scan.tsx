import { useState } from "react";
import { Header } from "@/components/header";
import { Footer } from "@/components/footer";
import { FileScanner } from "@/components/file-scanner";
import { ResultsModal } from "@/components/results-modal";
import type { ScanResult } from "@/lib/types";

export default function FileScan() {
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);

  const handleScanResult = (result: ScanResult) => {
    setScanResult(result);
  };

  const handleCloseResults = () => {
    setScanResult(null);
  };

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Header />
      <main>
        <FileScanner onResult={handleScanResult} />
        {scanResult && (
          <ResultsModal result={scanResult} onClose={handleCloseResults} />
        )}
      </main>
      <Footer />
    </div>
  );
}
