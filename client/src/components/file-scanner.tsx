import { useState, useCallback } from "react";
import { useMutation } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Upload, CloudUpload, File } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { nb } from "@/lib/i18n/nb";
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
      try {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('fileName', file.name);
        
        const response = await fetch('/api/scan-file', {
          method: 'POST',
          body: formData,
        });
        
        if (!response.ok) {
          throw new Error(`Upload failed: ${response.statusText}`);
        }
        
        const result = await response.json();
        return result;
      } catch (error) {
        throw error instanceof Error ? error : new Error(nb.errors.uploadFailed);
      }
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
        title: nb.errors.scanFailed,
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const handleFileSelect = useCallback((file: File) => {
    if (file.size > 32 * 1024 * 1024) { // 32MB limit
      toast({
        title: nb.errors.fileTooBig,
        description: nb.errors.fileTooLargeDescription,
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
    <div className="w-full space-y-6" data-testid="file-scanner">
      {/* File Upload Area */}
      <div className="text-center">
        <Card 
          className={`border-2 border-dashed transition-colors cursor-pointer bg-slate-700/30 ${
            dragOver 
              ? 'border-blue-400 bg-blue-400/10' 
              : 'border-slate-600 hover:border-blue-400/50'
          }`}
          onDrop={handleDrop}
          onDragOver={(e) => {
            e.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          data-testid="file-drop-zone"
        >
          <CardContent className="p-16">
            <div className="text-center">
              <div className="w-20 h-20 bg-blue-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
                <CloudUpload className="text-blue-400 h-10 w-10" />
              </div>
              <h3 className="text-lg font-medium text-white mb-3">
                {nb.fileScanner.dropZoneText}
              </h3>
              <p className="text-slate-400 mb-6">
                {nb.fileScanner.supportedTypes} ({nb.fileScanner.maxSize})
              </p>
              
              <input 
                type="file" 
                id="file-upload" 
                className="hidden" 
                accept="*/*"
                onChange={handleFileInput}
                disabled={scanMutation.isPending}
                data-testid="input-file"
              />
              <label htmlFor="file-upload">
                <Button 
                  asChild 
                  disabled={scanMutation.isPending}
                  className="bg-blue-500 hover:bg-blue-600 text-white h-12 px-8 text-lg font-semibold"
                  data-testid="button-choose-file"
                >
                  <span className="cursor-pointer">
                    <Upload className="mr-2 h-5 w-5" />
                    {nb.main.chooseFile}
                  </span>
                </Button>
              </label>
            </div>

            {/* Upload Progress */}
            {scanMutation.isPending && selectedFile && (
              <div className="mt-8" data-testid="upload-progress">
                <Card className="bg-slate-800 border-slate-600">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center space-x-2">
                        <File className="h-4 w-4 text-blue-400" />
                        <span className="text-sm font-medium text-white">{selectedFile.name}</span>
                      </div>
                      <span className="text-sm text-slate-400">{nb.fileScanner.scanning}</span>
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
  );
}
