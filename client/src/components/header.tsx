import { useState } from "react";
import { Link, useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet";
import { Avatar, AvatarImage, AvatarFallback } from "@/components/ui/avatar";
import { Menu, Shield, LogOut, User } from "lucide-react";
import { nb } from "@/lib/i18n/nb";
import { useAuth } from "@/hooks/useAuth";

export function Header() {
  const [location] = useLocation();
  const [isOpen, setIsOpen] = useState(false);
  const { user, isAuthenticated } = useAuth();

  const navigation = [
    { name: nb.nav.dashboard, href: "/admin" },
  ];

  const handleLogout = () => {
    window.location.href = "/api/logout";
  };

  const handleLogin = () => {
    window.location.href = "/api/login";
  };

  return (
    <header className="border-b border-slate-700 bg-slate-800">
      <div className="container mx-auto px-4 py-4 flex items-center justify-between">
        <Link href="/" className="flex items-center space-x-3" data-testid="link-home">
          <div className="w-10 h-10 bg-gradient-to-br from-primary to-primary/80 rounded-lg flex items-center justify-center">
            <Shield className="text-white text-lg" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-foreground">{nb.appName}</h1>
            <p className="text-xs text-muted-foreground">{nb.tagline}</p>
          </div>
        </Link>

        {/* Desktop Navigation */}
        <nav className="hidden md:flex items-center space-x-6">
          {navigation.map((item) => (
            <Link
              key={item.name}
              href={item.href}
              className={`text-muted-foreground hover:text-foreground transition-colors ${
                location === item.href ? "text-foreground font-medium" : ""
              }`}
              data-testid={`link-${item.name.toLowerCase().replace(" ", "-")}`}
            >
              {item.name}
            </Link>
          ))}
          
          {isAuthenticated && user ? (
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <Avatar className="h-8 w-8">
                  <AvatarImage 
                    src={user.profileImageUrl || undefined} 
                    alt={user.email || 'User'} 
                    style={{ objectFit: 'cover' }}
                  />
                  <AvatarFallback>
                    <User className="h-4 w-4" />
                  </AvatarFallback>
                </Avatar>
                <span className="text-sm text-foreground">
                  {user.firstName || user.email}
                </span>
              </div>
              <Button 
                variant="ghost" 
                size="sm" 
                onClick={handleLogout}
                data-testid="button-logout"
              >
                <LogOut className="h-4 w-4 mr-2" />
                {nb.auth.logout}
              </Button>
            </div>
          ) : (
            <Button onClick={handleLogin} data-testid="button-sign-in">
              {nb.auth.login}
            </Button>
          )}
        </nav>

        {/* Mobile Navigation */}
        <Sheet open={isOpen} onOpenChange={setIsOpen}>
          <SheetTrigger asChild className="md:hidden">
            <Button variant="ghost" size="icon" data-testid="button-menu">
              <Menu className="h-5 w-5" />
            </Button>
          </SheetTrigger>
          <SheetContent side="right">
            <nav className="flex flex-col space-y-4 mt-8">
              {navigation.map((item) => (
                <Link
                  key={item.name}
                  href={item.href}
                  onClick={() => setIsOpen(false)}
                  className={`text-muted-foreground hover:text-foreground transition-colors ${
                    location === item.href ? "text-foreground font-medium" : ""
                  }`}
                  data-testid={`mobile-link-${item.name.toLowerCase().replace(" ", "-")}`}
                >
                  {item.name}
                </Link>
              ))}
              
              {isAuthenticated && user ? (
                <div className="flex flex-col space-y-3 pt-4 border-t border-border">
                  <div className="flex items-center space-x-2">
                    <Avatar className="h-8 w-8">
                      <AvatarImage 
                        src={user.profileImageUrl || undefined} 
                        alt={user.email || 'User'}
                        style={{ objectFit: 'cover' }}
                      />
                      <AvatarFallback>
                        <User className="h-4 w-4" />
                      </AvatarFallback>
                    </Avatar>
                    <span className="text-sm text-foreground">
                      {user.firstName || user.email}
                    </span>
                  </div>
                  <Button 
                    variant="ghost" 
                    onClick={handleLogout}
                    data-testid="mobile-button-logout"
                    className="justify-start"
                  >
                    <LogOut className="h-4 w-4 mr-2" />
                    {nb.auth.logout}
                  </Button>
                </div>
              ) : (
                <Button className="mt-4" onClick={handleLogin} data-testid="mobile-button-sign-in">
                  {nb.auth.login}
                </Button>
              )}
            </nav>
          </SheetContent>
        </Sheet>
      </div>
    </header>
  );
}
