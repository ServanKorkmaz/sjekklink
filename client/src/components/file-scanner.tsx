import { useState, useCallback } from "react";
import { useMutation } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Upload, CloudUpload, File } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { ScanResult } from "@/lib/types";

interface FileScannerProps {
  onResult: (result: ScanResult) => void;
}

export function FileScanner({ onResult }: FileScannerProps) {
  const [dragOver, setDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [progress, setProgress] = useState(0);
  const { toast } = useToast();

  const scanMutation = useMutation({
    mutationFn: async (file: File) => {
      return new Promise<ScanResult>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = async () => {
          try {
            const buffer = reader.result as ArrayBuffer;
            const base64 = btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(buffer))));
            
            const response = await apiRequest("POST", "/api/scan-file", {
              fileBuffer: base64,
              fileName: file.name,
            });
            
            const result = await response.json();
            resolve(result);
          } catch (error) {
            reject(error);
          }
        };
        reader.onerror = () => reject(new Error('Failed to read file'));
        reader.readAsArrayBuffer(file);
      });
    },
    onMutate: () => {
      setProgress(0);
      const interval = setInterval(() => {
        setProgress((prev) => {
          if (prev >= 90) {
            clearInterval(interval);
            return 90;
          }
          return prev + 15;
        });
      }, 300);
    },
    onSuccess: (result: ScanResult) => {
      setProgress(100);
      setTimeout(() => {
        onResult(result);
        setProgress(0);
        setSelectedFile(null);
      }, 500);
    },
    onError: (error: Error) => {
      setProgress(0);
      setSelectedFile(null);
      toast({
        title: "Scan Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const handleFileSelect = useCallback((file: File) => {
    if (file.size > 32 * 1024 * 1024) { // 32MB limit
      toast({
        title: "File Too Large",
        description: "Please select a file smaller than 32MB",
        variant: "destructive",
      });
      return;
    }
    
    setSelectedFile(file);
    scanMutation.mutate(file);
  }, [scanMutation, toast]);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    
    const files = Array.from(e.dataTransfer.files);
    if (files.length > 0) {
      handleFileSelect(files[0]);
    }
  }, [handleFileSelect]);

  const handleFileInput = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      handleFileSelect(files[0]);
    }
    e.target.value = ''; // Reset input
  }, [handleFileSelect]);

  return (
    <section className="py-20 bg-muted" data-testid="file-scanner">
      <div className="container mx-auto px-4">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-3xl md:text-4xl font-bold text-foreground mb-6">
            Scan Files for Malware
          </h2>
          <p className="text-xl text-muted-foreground mb-12 max-w-2xl mx-auto">
            Upload files to check for viruses, trojans, and other malicious software using multiple security engines.
          </p>

          {/* File Upload Area */}
          <Card 
            className={`border-2 border-dashed transition-colors cursor-pointer ${
              dragOver 
                ? 'border-primary bg-primary/5' 
                : 'border-border hover:border-primary'
            }`}
            onDrop={handleDrop}
            onDragOver={(e) => {
              e.preventDefault();
              setDragOver(true);
            }}
            onDragLeave={() => setDragOver(false)}
            data-testid="file-drop-zone"
          >
            <CardContent className="p-12">
              <div className="text-center">
                <div className="w-20 h-20 bg-primary/10 rounded-full flex items-center justify-center mx-auto mb-6">
                  <CloudUpload className="text-3xl text-primary" />
                </div>
                <h3 className="text-xl font-semibold mb-3">
                  Drag a file here or choose from disk
                </h3>
                <p className="text-muted-foreground mb-6">
                  Support for .exe, .zip, .pdf, .docx and other file types (Max 32MB)
                </p>
                
                <input 
                  type="file" 
                  id="file-upload" 
                  className="hidden" 
                  onChange={handleFileInput}
                  disabled={scanMutation.isPending}
                  data-testid="input-file"
                />
                <label htmlFor="file-upload">
                  <Button 
                    asChild 
                    disabled={scanMutation.isPending}
                    data-testid="button-choose-file"
                  >
                    <span className="cursor-pointer">
                      <Upload className="mr-2 h-4 w-4" />
                      Choose File
                    </span>
                  </Button>
                </label>
              </div>

              {/* Upload Progress */}
              {scanMutation.isPending && selectedFile && (
                <div className="mt-8" data-testid="upload-progress">
                  <Card className="bg-muted border-0">
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center space-x-2">
                          <File className="h-4 w-4" />
                          <span className="text-sm font-medium">{selectedFile.name}</span>
                        </div>
                        <span className="text-sm text-muted-foreground">Scanning...</span>
                      </div>
                      <Progress value={progress} className="w-full" />
                    </CardContent>
                  </Card>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </section>
  );
}
