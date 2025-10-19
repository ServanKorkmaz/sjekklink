# Overview

TryggLink is a comprehensive security scanner web application designed to analyze URLs and files for potential threats. The application provides users with risk assessments, detailed security reports, and threat intelligence from multiple security providers. Built as a full-stack web application, it combines a modern React frontend with an Express.js backend, utilizing PostgreSQL for data persistence and implementing real-time scanning capabilities.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Frontend Architecture
The frontend is built using React with TypeScript and modern development practices:
- **Framework**: React 18 with TypeScript for type safety
- **Styling**: Tailwind CSS with shadcn/ui component library for consistent design
- **Routing**: Wouter for lightweight client-side routing
- **State Management**: TanStack Query (React Query) for server state management
- **Forms**: React Hook Form with Zod validation for type-safe form handling
- **Build Tool**: Vite for fast development and optimized production builds

The application follows a component-based architecture with clear separation of concerns:
- Pages handle routing and layout composition
- Components implement specific UI functionality
- Hooks manage shared logic and state
- Type definitions ensure consistency across the application

## Backend Architecture
The backend uses Express.js with TypeScript in a modular structure:
- **Framework**: Express.js with middleware for request handling
- **Database ORM**: Drizzle ORM for type-safe database operations
- **API Design**: RESTful endpoints with proper error handling and rate limiting
- **Authentication**: Replit Auth (OpenID Connect) with session management
- **File Processing**: Multer for file uploads (max 32MB) with filename sanitization
- **Caching**: Built-in result caching to reduce API costs and improve performance

Key architectural decisions include:
- Provider pattern for external security services (Google Safe Browsing, PhishTank, VirusTotal)
- Rate limiting middleware to prevent abuse (10 requests per minute)
- Comprehensive logging for monitoring and debugging
- Modular storage interface for future database migration flexibility
- Protected admin endpoints requiring authentication

## Data Storage
The application uses PostgreSQL with Drizzle ORM for robust data management:
- **Primary Database**: Neon PostgreSQL for scalable cloud database hosting
- **Schema Design**: Four main entities - users (with email, firstName, lastName, profileImageUrl), sessions, scan results, and API usage tracking
- **Data Types**: JSONB for flexible metadata storage and arrays for reason lists
- **Session Storage**: PostgreSQL-backed session store using connect-pg-simple
- **Migrations**: Drizzle Kit for version-controlled database schema changes

The database schema supports both URL and file scanning with shared result structures, enabling unified reporting and analytics. User authentication sessions are persisted in the database for secure, scalable session management.

## Security and Risk Assessment
The core security engine implements a multi-provider approach:
- **Provider Interface**: Abstracted security check providers for modularity
- **Scoring Algorithm**: Weighted risk scoring from 0-100 based on multiple factors
- **Threat Intelligence**: Integration with Google Safe Browsing, PhishTank, VirusTotal, and WHOIS data
- **Heuristic Analysis**: Custom algorithms for domain age, URL patterns, and suspicious characteristics
- **File Analysis**: VirusTotal integration for comprehensive malware detection (both URL and file scanning)
- **Authentication Security**: Replit Auth (OIDC) with secure session management and protected admin routes
- **Input Validation**: Filename sanitization to prevent path traversal and injection attacks

Risk assessment combines quantitative scores with qualitative reasons, providing users with both overall risk levels and detailed explanations. The application gracefully degrades to heuristic analysis when external security APIs are unavailable.

# External Dependencies

## Security Providers
- **Google Safe Browsing**: Web Risk API for known malicious URL detection
- **PhishTank**: Community-driven phishing database for URL reputation
- **VirusTotal**: Active integration for both URL and file scanning with multi-engine malware detection
- **WHOIS/RDAP**: Domain registration and age verification services
- **AbuseIPDB**: IP reputation and geolocation data

## Authentication
- **Replit Auth**: OpenID Connect authentication with Google, GitHub, and email/password support
- **Session Management**: PostgreSQL-backed sessions with secure cookie settings
- **Protected Routes**: Admin dashboard and admin API endpoints require authentication

## Cloud Services
- **Neon Database**: PostgreSQL hosting with serverless scaling
- **Google Cloud Storage**: File storage and processing capabilities (configured but not actively used)

## Development and Build Tools
- **Vite**: Frontend build tool with hot module replacement
- **Drizzle Kit**: Database migration and schema management
- **TypeScript**: Type checking and development tooling
- **TanStack Query**: Server state management and caching
- **Zod**: Runtime type validation and schema parsing

## UI and User Experience
- **Radix UI**: Accessible component primitives
- **Tailwind CSS**: Utility-first CSS framework
- **Lucide React**: Icon library for consistent iconography
- **React Icons**: Additional icon sets for social media and branding
- **date-fns**: Date formatting and manipulation utilities

The application is designed for deployment on Replit with environment-specific configurations and includes development-friendly features like error overlays and hot reloading.