import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useMutation } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Form, FormControl, FormField, FormItem, FormMessage } from "@/components/ui/form";
import { Progress } from "@/components/ui/progress";
import { Search, Shield, Database, Globe } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { nb } from "@/lib/i18n/nb";
import type { ScanResult } from "@/lib/types";

const urlSchema = z.object({
  url: z.string().url(nb.errors.invalidUrl),
});

type UrlFormData = z.infer<typeof urlSchema>;

interface UrlScannerProps {
  onResult: (result: ScanResult) => void;
}

export function UrlScanner({ onResult }: UrlScannerProps) {
  const [progress, setProgress] = useState(0);
  const { toast } = useToast();

  const form = useForm<UrlFormData>({
    resolver: zodResolver(urlSchema),
    defaultValues: {
      url: "",
    },
  });

  const scanMutation = useMutation({
    mutationFn: async (data: UrlFormData) => {
      const response = await apiRequest("POST", "/api/check-url", data);
      return response.json();
    },
    onMutate: () => {
      setProgress(0);
      const interval = setInterval(() => {
        setProgress((prev) => {
          if (prev >= 90) {
            clearInterval(interval);
            return 90;
          }
          return prev + 10;
        });
      }, 200);
    },
    onSuccess: (result: ScanResult) => {
      setProgress(100);
      setTimeout(() => {
        onResult(result);
        setProgress(0);
      }, 500);
    },
    onError: (error: Error) => {
      setProgress(0);
      toast({
        title: nb.errors.scanFailed,
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: UrlFormData) => {
    scanMutation.mutate(data);
  };

  return (
    <div className="w-full space-y-6" data-testid="url-scanner">
      {/* URL Input Form */}
      <div className="text-center">
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <div className="flex flex-col gap-4">
              <FormField
                control={form.control}
                name="url"
                render={({ field }) => (
                  <FormItem>
                    <FormControl>
                      <Input
                        placeholder={nb.main.urlPlaceholder}
                        {...field}
                        data-testid="input-url"
                        disabled={scanMutation.isPending}
                        className="bg-slate-700 border-slate-600 text-white placeholder-slate-400 h-12 text-center text-lg"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <Button 
                type="submit"
                disabled={scanMutation.isPending}
                data-testid="button-check-url"
                className="bg-blue-500 hover:bg-blue-600 text-white h-12 text-lg font-semibold"
              >
                <Search className="mr-2 h-5 w-5" />
                {nb.main.analyzeButton}
              </Button>
            </div>
            
            {/* Loading State */}
            {scanMutation.isPending && (
              <div className="space-y-3" data-testid="loading-state">
                <div className="flex items-center justify-center space-x-2 text-slate-300">
                  <Search className="h-4 w-4 animate-spin" />
                  <span>{nb.urlScanner.scanning}</span>
                </div>
                <Progress value={progress} className="w-full" />
              </div>
            )}
          </form>
        </Form>
      </div>

      {/* Trust Indicators */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm text-slate-400">
        <div className="flex items-center justify-center space-x-2">
          <Shield className="text-blue-400 h-4 w-4" />
          <span>{nb.securityChecks.googleSafeBrowsing}</span>
        </div>
        <div className="flex items-center justify-center space-x-2">
          <Database className="text-blue-400 h-4 w-4" />
          <span>{nb.securityChecks.ipReputation}</span>
        </div>
        <div className="flex items-center justify-center space-x-2">
          <Globe className="text-blue-400 h-4 w-4" />
          <span>{nb.securityChecks.domainAnalysis}</span>
        </div>
      </div>
    </div>
  );
}
