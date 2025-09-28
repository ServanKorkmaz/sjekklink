import { Shield } from "lucide-react";
import { FaTwitter, FaGithub, FaLinkedin } from "react-icons/fa";
import { nb } from "@/lib/i18n/nb";

export function Footer() {
  const productLinks = [
    { name: nb.footer.productLinks.urlScanner, href: "#" },
    { name: nb.footer.productLinks.fileScanner, href: "#" },
    { name: nb.footer.productLinks.apiAccess, href: "#" },
    { name: nb.footer.productLinks.enterprise, href: "#" },
  ];

  const legalLinks = [
    { name: nb.footer.legalLinks.privacyPolicy, href: "#" },
    { name: nb.footer.legalLinks.termsOfService, href: "#" },
    { name: nb.footer.legalLinks.contact, href: "#" },
    { name: nb.footer.legalLinks.support, href: "#" },
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
                <h3 className="text-xl font-bold text-foreground">{nb.appName}</h3>
                <p className="text-xs text-muted-foreground">{nb.tagline}</p>
              </div>
            </div>
            <p className="text-muted-foreground mb-4 max-w-md">
              {nb.footer.description}
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
            <h4 className="font-semibold text-foreground mb-4">{nb.footer.product}</h4>
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
            <h4 className="font-semibold text-foreground mb-4">{nb.footer.legal}</h4>
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
            {nb.footer.copyright}<br/>
            {nb.footer.disclaimer}
          </p>
        </div>
      </div>
    </footer>
  );
}
