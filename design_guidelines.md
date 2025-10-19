# TryggLink Authentication Gate Design Guidelines

## Design Approach
**Reference-Based:** VirusTotal dark theme security aesthetic with professional Nordic design sensibility. Focused on trust, clarity, and technical credibility.

## Core Design Elements

### A. Color Palette
**Dark Mode Foundation:**
- Background layers: bg-slate-900 (main), bg-slate-800 (cards), bg-slate-700 (inputs)
- Primary accent: 200 85% 55% (cyan-blue for CTAs, links, focus states)
- Success states: 150 70% 50% (secure green indicators)
- Error states: 0 75% 60% (alert red)
- Text hierarchy: slate-50 (headings), slate-300 (body), slate-400 (labels), slate-500 (muted)
- Borders: slate-700 (default), slate-600 (hover), primary accent (focus)

### B. Typography
**Font Stack:** Inter or similar Norwegian-friendly sans-serif via Google Fonts
- Headings: 600-700 weight, tight tracking
- Body: 400-500 weight, relaxed leading (1.6)
- Labels: 500 weight, uppercase tracking for form fields
- Scale: text-4xl (heading), text-base (body), text-sm (labels), text-xs (helper text)

### C. Layout System
**Spacing Primitives:** Tailwind units of 2, 4, 6, 8, 12, 16, 24
- Card padding: p-8 to p-12
- Input spacing: py-3, px-4
- Section gaps: space-y-6 for forms
- Container width: max-w-md (centered login card)

### D. Component Library

**Authentication Card:**
- Centered vertically and horizontally on full viewport (min-h-screen flex items-center justify-center)
- Card: bg-slate-800 with subtle border (border-slate-700), rounded-2xl, shadow-2xl with colored glow
- Width: max-w-md with px-6 margins
- Inner padding: p-8 lg:p-12

**Header Section:**
- Logo/icon: 64px technical shield or lock icon in primary accent color
- App name: "TryggLink" in text-3xl font-bold text-slate-50
- Tagline: "Sikkerhetsskanning" in text-sm text-slate-400
- Trust badge: Small text like "Beskyttet tilkobling" with lock icon

**Form Elements:**
- Input containers: space-y-6
- Labels: text-sm font-medium text-slate-300 mb-2
- Input fields: bg-slate-700 border-slate-600 text-slate-50, rounded-lg, py-3 px-4, focus:ring-2 focus:ring-primary focus:border-primary
- Placeholders: text-slate-500
- Password field: Toggle visibility icon (eye/eye-slash) in slate-400

**Action Buttons:**
- Primary CTA: Full width, bg-primary (cyan-blue gradient), text-white, font-semibold, py-3, rounded-lg
- Secondary links: text-primary hover:text-primary-lighter, text-sm

**Additional Trust Elements:**
- Security indicator bar below form: "256-bit kryptering" with shield icon
- Footer text: "Personvern" and "Vilkår" links in text-xs text-slate-500
- Optional SSO buttons: Outlined buttons with provider logos, bg-slate-700/50 backdrop-blur

**Alternative Actions:**
- "Glemt passord?" link aligned right, text-sm text-primary
- "Ingen konto? Registrer deg" centered below main button, text-slate-400 with text-primary accent on link

**Background Treatment:**
- Subtle radial gradient: from-slate-900 via-slate-900 to-slate-800
- Optional: Faint grid pattern overlay (repeating-linear-gradient) at 0.5 opacity for technical aesthetic
- Floating blur orbs: Absolute positioned circles with primary accent at 0.1 opacity, blur-3xl

### E. Animations
**Minimal, purposeful:**
- Form field focus: Smooth border color transition (150ms)
- Button hover: Slight brightness increase, no transform
- Card entry: Subtle fade-in (opacity 0 to 1, 300ms)

## Images

**No Large Hero Image** - Authentication gates should be focused and functional.

**Subtle Background Graphics:**
- Optional abstract security-themed SVG pattern in background (circuit board lines, network nodes, shield patterns)
- Rendered at very low opacity (0.03-0.05) in primary accent color
- Positioned absolutely, full viewport, z-index behind card

**Logo/Brand Mark:**
- 64x64px icon in card header
- SVG shield with TryggLink initial or abstract security symbol
- Primary accent color with subtle glow effect

## Critical Specifications

**Responsive Behavior:**
- Mobile: Full viewport height, card becomes full-width with rounded-t-3xl only, px-6 py-8
- Desktop: Centered card with max-w-md, dramatic shadow and backdrop

**Norwegian Language Elements:**
- Email field label: "E-postadresse"
- Password field: "Passord"
- Login button: "Logg inn"
- Remember me: "Husk meg"
- Form validation in Norwegian

**Security Visual Cues:**
- SSL indicator in footer
- "Sikker pålogging" badge with lock icon
- Subtle green pulse on active security indicator

**Accessibility:**
- All form inputs with proper labels and aria-labels
- Keyboard navigation: Clear focus states with visible ring
- Error messages: Red accent with icon, announced to screen readers

This creates a professional, trust-inspiring authentication experience that matches TryggLink's security-focused dark aesthetic while maintaining Norwegian cultural expectations for clean, functional design.