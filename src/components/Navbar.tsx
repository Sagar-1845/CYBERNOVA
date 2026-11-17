import React, { useState, useEffect } from 'react';
import { NavLink, Link, useLocation } from 'react-router-dom';
import {
  Shield,
  Sun,
  Moon,
  Lock,
  Menu,
  X,
  Play,
  FileCheck2,
  BarChart3,
  Database,
  FileText,
  Scale,
  Scissors,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';

interface NavbarProps {
  theme: 'dark' | 'light';
  onToggleTheme: () => void;
}

const NAV_LINKS = [
  { name: 'Gateway Demo', path: '/demo', icon: Play },
  { name: 'DPDP Consent & Rights', path: '/consent', icon: Scale },
  { name: 'Document Intelligence', path: '/documents', icon: FileText },
  { name: 'Scan & Redact', path: '/scan-redact', icon: Scissors },
  { name: 'Audit Log', path: '/audit', icon: FileCheck2 },
  { name: 'Metrics', path: '/metrics', icon: BarChart3 },
  { name: 'Dataset', path: '/dataset', icon: Database },
];

export const Navbar: React.FC<NavbarProps> = ({ theme, onToggleTheme }) => {
  const [scrolled, setScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);
  const location = useLocation();

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 15);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  // Close mobile menu on route change
  useEffect(() => {
    setMobileMenuOpen(false);
  }, [location.pathname]);

  // Check live backend connection status
  useEffect(() => {
    const checkBackend = async () => {
      try {
        const res = await fetch('/health');
        if (res.ok) {
          setBackendOnline(true);
        } else {
          setBackendOnline(false);
        }
      } catch {
        setBackendOnline(false);
      }
    };
    checkBackend();
    const interval = setInterval(checkBackend, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header
      className={cn(
        'fixed top-0 left-0 right-0 z-50 transition-all duration-300',
        scrolled || mobileMenuOpen
          ? 'bg-background/95 backdrop-blur-md border-b border-border shadow-lg'
          : 'bg-background/80 backdrop-blur-sm border-b border-border/50'
      )}
    >
      <div className="container mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
        {/* Brand Logo */}
        <Link
          to="/"
          className="flex items-center gap-3 group focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 rounded-xl p-1"
          aria-label="ZEROLEAK AI Home"
        >
          <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-card border border-border shadow-md transition-transform group-hover:scale-105">
            {/* Tricolor Accent Notch */}
            <div className="absolute -top-[1px] left-2 right-2 h-[2px] flex rounded-full overflow-hidden">
              <span className="flex-1 bg-amber-500" />
              <span className="flex-1 bg-white/70" />
              <span className="flex-1 bg-emerald-500" />
            </div>
            <Shield className="w-5 h-5 text-cyan-400 transition-colors group-hover:text-amber-400" />
            <span className="absolute -bottom-0.5 -right-0.5 w-2 h-2 rounded-full bg-cyan-400 shadow-sm" />
          </div>

          <div className="flex flex-col">
            <span className="font-extrabold text-base sm:text-lg tracking-tight text-foreground leading-none">
              ZERO<span className="text-cyan-400">LEAK</span> <span className="text-xs text-amber-400 font-bold">AI</span>
            </span>
            <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider">
              Privacy Firewall & DPDP
            </span>
          </div>
        </Link>

        {/* Desktop Navigation Links */}
        <nav className="hidden lg:flex items-center gap-1 bg-card/60 border border-border/80 px-2 py-1.5 rounded-full backdrop-blur-md shadow-sm">
          <NavLink
            to="/"
            end
            className={({ isActive }) =>
              cn(
                'px-3 py-1.5 rounded-full text-xs font-mono font-medium transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400',
                isActive
                  ? 'bg-secondary text-foreground font-semibold shadow-sm border border-border'
                  : 'text-muted-foreground hover:text-foreground'
              )
            }
          >
            Overview
          </NavLink>

          {NAV_LINKS.map((link) => {
            const Icon = link.icon;
            return (
              <NavLink
                key={link.path}
                to={link.path}
                className={({ isActive }) =>
                  cn(
                    'px-3 py-1.5 rounded-full text-xs font-mono font-medium transition-all flex items-center gap-1.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400',
                    isActive
                      ? 'bg-secondary text-foreground font-semibold shadow-sm border border-border'
                      : 'text-muted-foreground hover:text-foreground'
                  )
                }
              >
                <Icon className="w-3.5 h-3.5 text-cyan-400" />
                <span>{link.name}</span>
              </NavLink>
            );
          })}
        </nav>

        {/* Right Action Controls */}
        <div className="flex items-center gap-2 sm:gap-3">
          {/* Live Backend Connection Status Indicator */}
          <div className="hidden xl:flex items-center gap-2 text-xs font-mono text-muted-foreground bg-card/60 border border-border/70 px-3 py-1.5 rounded-full">
            {backendOnline ? (
              <>
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                <span className="text-[11px] text-emerald-400 font-medium">FastAPI :8000 Live</span>
              </>
            ) : (
              <>
                <span className="w-2 h-2 rounded-full bg-cyan-400" />
                <span className="text-[11px] text-foreground/80 font-medium">Sovereign Enclave Active</span>
              </>
            )}
          </div>

          {/* Theme Switcher Button */}
          <Button
            variant="outline"
            size="icon"
            onClick={onToggleTheme}
            aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
            className="rounded-xl border-border/80 min-h-[44px] min-w-[44px] h-11 w-11 text-foreground hover:text-cyan-400 transition-all focus-visible:ring-2 focus-visible:ring-cyan-400"
          >
            {theme === 'dark' ? (
              <Sun className="h-4 w-4 text-amber-400 transition-transform hover:rotate-45" />
            ) : (
              <Moon className="h-4 w-4 text-slate-700 transition-transform hover:-rotate-12" />
            )}
          </Button>

          {/* Mobile Menu Toggle Button */}
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-expanded={mobileMenuOpen}
            aria-label={mobileMenuOpen ? 'Close navigation menu' : 'Open navigation menu'}
            className="lg:hidden rounded-xl min-h-[44px] min-w-[44px] h-11 w-11 text-foreground focus-visible:ring-2 focus-visible:ring-cyan-400"
          >
            {mobileMenuOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </Button>
        </div>
      </div>

      {/* Mobile Drawer Menu */}
      {mobileMenuOpen && (
        <div className="lg:hidden border-b border-border bg-background/98 backdrop-blur-xl px-4 pt-3 pb-6 space-y-2 animate-in slide-in-from-top duration-200">
          <NavLink
            to="/"
            end
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-sm font-mono transition-colors min-h-[44px]',
                isActive
                  ? 'bg-secondary text-foreground font-semibold border border-border'
                  : 'text-muted-foreground hover:text-foreground'
              )
            }
          >
            Overview
          </NavLink>

          {NAV_LINKS.map((link) => {
            const Icon = link.icon;
            return (
              <NavLink
                key={link.path}
                to={link.path}
                className={({ isActive }) =>
                  cn(
                    'flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-sm font-mono transition-colors min-h-[44px]',
                    isActive
                      ? 'bg-secondary text-foreground font-semibold border border-border'
                      : 'text-muted-foreground hover:text-foreground'
                  )
                }
              >
                <Icon className="w-4 h-4 text-cyan-400" />
                <span>{link.name}</span>
              </NavLink>
            );
          })}
        </div>
      )}
    </header>
  );
};
export default Navbar;
