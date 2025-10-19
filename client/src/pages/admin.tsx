import { Header } from "@/components/header";
import { Footer } from "@/components/footer";
import { AdminDashboard } from "@/components/admin-dashboard";
import { useAuth } from "@/hooks/useAuth";
import { nb } from "@/lib/i18n/nb";
import { Button } from "@/components/ui/button";
import { Shield, Lock, UserPlus } from "lucide-react";

export default function Admin() {
  const { isAuthenticated, isLoading } = useAuth();

  // Show loading state
  if (isLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-900 to-slate-800 text-foreground flex items-center justify-center">
        <div className="text-center">
          <div className="text-xl text-slate-300">{nb.common.loading}</div>
        </div>
      </div>
    );
  }

  // Show authentication gate if not authenticated
  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-900 to-slate-800">
        <Header />
        <main className="flex items-center justify-center px-4 py-16">
          <div className="w-full max-w-md">
            {/* Authentication Card */}
            <div className="bg-slate-800 border border-slate-700 rounded-2xl shadow-2xl p-8 lg:p-12 space-y-6">
              {/* Icon and Title */}
              <div className="text-center space-y-4">
                <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-primary/10 border border-primary/20">
                  <Shield className="w-8 h-8 text-primary" />
                </div>
                <div>
                  <h1 className="text-2xl font-bold text-slate-50 mb-2">
                    {nb.admin.authGate.title}
                  </h1>
                  <p className="text-sm text-slate-400">
                    {nb.admin.authGate.subtitle}
                  </p>
                </div>
              </div>

              {/* Description */}
              <div className="bg-slate-900/50 border border-slate-700/50 rounded-lg p-4">
                <p className="text-sm text-slate-300 leading-relaxed">
                  {nb.admin.authGate.description}
                </p>
              </div>

              {/* Action Buttons */}
              <div className="space-y-3">
                <Button 
                  onClick={() => window.location.href = "/api/login"}
                  className="w-full py-6 text-base font-semibold"
                  data-testid="button-login-admin"
                >
                  <UserPlus className="w-5 h-5 mr-2" />
                  {nb.admin.authGate.createAccountButton}
                </Button>
                
                <div className="text-center">
                  <p className="text-sm text-slate-400">
                    {nb.admin.authGate.alreadyHaveAccount}{' '}
                    <button 
                      onClick={() => window.location.href = "/api/login"}
                      className="text-primary hover:text-primary/80 font-medium transition-colors"
                      data-testid="link-login-existing"
                    >
                      {nb.admin.authGate.loginLink}
                    </button>
                  </p>
                </div>
              </div>

              {/* Security Badge */}
              <div className="pt-4 border-t border-slate-700">
                <div className="flex items-center justify-center gap-2 text-xs text-slate-500">
                  <Lock className="w-3 h-3" />
                  <span>{nb.admin.authGate.securityBadge}</span>
                </div>
              </div>
            </div>

            {/* Additional Info */}
            <div className="mt-6 text-center">
              <p className="text-xs text-slate-500">
                {nb.admin.authGate.helpText}
              </p>
            </div>
          </div>
        </main>
        <Footer />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Header />
      <main>
        <AdminDashboard />
      </main>
      <Footer />
    </div>
  );
}
