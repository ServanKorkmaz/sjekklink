import { useState } from "react";
import { Link, useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet";
import { Menu, Shield } from "lucide-react";
import { nb } from "@/lib/i18n/nb";

export function Header() {
  const [location] = useLocation();
  const [isOpen, setIsOpen] = useState(false);

  const navigation = [
    { name: nb.nav.home, href: "/" },
    { name: nb.nav.fileScan, href: "/file-scan" },
    { name: nb.nav.dashboard, href: "/admin" },
  ];

  return (
    <header className="border-b border-border bg-card">
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
          <Button data-testid="button-sign-in">{nb.nav.signIn}</Button>
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
              <Button className="mt-4" data-testid="mobile-button-sign-in">
                {nb.nav.signIn}
              </Button>
            </nav>
          </SheetContent>
        </Sheet>
      </div>
    </header>
  );
}
