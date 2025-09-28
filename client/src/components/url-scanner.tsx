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
import type { ScanResult } from "@/lib/types";

const urlSchema = z.object({
  url: z.string().url("Please enter a valid URL"),
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
        title: "Scan Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: UrlFormData) => {
    scanMutation.mutate(data);
  };

  return (
    <section className="py-20 bg-gradient-to-br from-background to-muted">
      <div className="container mx-auto px-4 text-center">
        <div className="max-w-4xl mx-auto">
          <h1 className="text-4xl md:text-6xl font-bold text-foreground mb-6 leading-tight">
            Check if a link is safe<br />
            <span className="text-primary">before you click</span>
          </h1>
          <p className="text-xl text-muted-foreground mb-8 max-w-2xl mx-auto">
            Get instant security assessments for URLs and files. Results are indicators — always use common sense.
          </p>
          
          {/* URL Input Form */}
          <div className="bg-card rounded-xl shadow-lg border border-border p-8 max-w-2xl mx-auto mb-8">
            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
                <div className="flex flex-col md:flex-row gap-4">
                  <FormField
                    control={form.control}
                    name="url"
                    render={({ field }) => (
                      <FormItem className="flex-1">
                        <FormControl>
                          <Input
                            placeholder="https://example.com/suspicious-link"
                            {...field}
                            data-testid="input-url"
                            disabled={scanMutation.isPending}
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
                  >
                    <Search className="mr-2 h-4 w-4" />
                    Check Now
                  </Button>
                </div>
                
                {/* Loading State */}
                {scanMutation.isPending && (
                  <div className="space-y-3" data-testid="loading-state">
                    <div className="flex items-center justify-center space-x-2 text-muted-foreground">
                      <Search className="h-4 w-4 animate-spin" />
                      <span>Analyzing URL security...</span>
                    </div>
                    <Progress value={progress} className="w-full" />
                  </div>
                )}
              </form>
            </Form>
          </div>

          {/* Trust Indicators */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-3xl mx-auto text-sm text-muted-foreground">
            <div className="flex items-center justify-center space-x-2">
              <Shield className="text-primary h-4 w-4" />
              <span>Google Safe Browsing</span>
            </div>
            <div className="flex items-center justify-center space-x-2">
              <Database className="text-primary h-4 w-4" />
              <span>PhishTank Database</span>
            </div>
            <div className="flex items-center justify-center space-x-2">
              <Globe className="text-primary h-4 w-4" />
              <span>Domain Analysis</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
