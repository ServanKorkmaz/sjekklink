import { Shield } from "lucide-react";
import { FaTwitter, FaGithub, FaLinkedin } from "react-icons/fa";

export function Footer() {
  const productLinks = [
    { name: "URL Scanner", href: "#" },
    { name: "File Scanner", href: "#" },
    { name: "API Access", href: "#" },
    { name: "Enterprise", href: "#" },
  ];

  const legalLinks = [
    { name: "Privacy Policy", href: "#" },
    { name: "Terms of Service", href: "#" },
    { name: "Contact", href: "#" },
    { name: "Support", href: "#" },
  ];

  return (
    <footer className="bg-card border-t border-border py-12">
      <div className="container mx-auto px-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          {/* Logo and Description */}
          <div className="col-span-1 md:col-span-2">
            <div className="flex items-center space-x-3 mb-4">
              <div className="w-10 h-10 bg-gradient-to-br from-primary to-primary/80 rounded-lg flex items-center justify-center">
                <Shield className="text-white text-lg" />
              </div>
              <div>
                <h3 className="text-xl font-bold text-foreground">TryggLink</h3>
                <p className="text-xs text-muted-foreground">Security Scanner</p>
              </div>
            </div>
            <p className="text-muted-foreground mb-4 max-w-md">
              Protecting users from malicious URLs and files with comprehensive security analysis and real-time threat detection.
            </p>
            <div className="flex space-x-4">
              <a href="#" className="text-muted-foreground hover:text-primary transition-colors" data-testid="link-twitter">
                <FaTwitter className="text-xl" />
              </a>
              <a href="#" className="text-muted-foreground hover:text-primary transition-colors" data-testid="link-github">
                <FaGithub className="text-xl" />
              </a>
              <a href="#" className="text-muted-foreground hover:text-primary transition-colors" data-testid="link-linkedin">
                <FaLinkedin className="text-xl" />
              </a>
            </div>
          </div>

          {/* Product Links */}
          <div>
            <h4 className="font-semibold text-foreground mb-4">Product</h4>
            <ul className="space-y-2">
              {productLinks.map((link) => (
                <li key={link.name}>
                  <a 
                    href={link.href} 
                    className="text-muted-foreground hover:text-primary transition-colors"
                    data-testid={`link-${link.name.toLowerCase().replace(/\s+/g, "-")}`}
                  >
                    {link.name}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Legal Links */}
          <div>
            <h4 className="font-semibold text-foreground mb-4">Legal</h4>
            <ul className="space-y-2">
              {legalLinks.map((link) => (
                <li key={link.name}>
                  <a 
                    href={link.href} 
                    className="text-muted-foreground hover:text-primary transition-colors"
                    data-testid={`link-${link.name.toLowerCase().replace(/\s+/g, "-")}`}
                  >
                    {link.name}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        </div>

        <div className="border-t border-border mt-8 pt-8 text-center">
          <p className="text-muted-foreground text-sm">
            © 2024 TryggLink. All rights reserved. Security indications only - not legal proof.
          </p>
        </div>
      </div>
    </footer>
  );
}
