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
- **File Processing**: Base64 encoding for file uploads with hash-based deduplication
- **Caching**: Built-in result caching to reduce API costs and improve performance

Key architectural decisions include:
- Provider pattern for external security services (Google Safe Browsing, PhishTank, etc.)
- Rate limiting middleware to prevent abuse
- Comprehensive logging for monitoring and debugging
- Modular storage interface for future database migration flexibility

## Data Storage
The application uses PostgreSQL with Drizzle ORM for robust data management:
- **Primary Database**: Neon PostgreSQL for scalable cloud database hosting
- **Schema Design**: Three main entities - users, scan results, and API usage tracking
- **Data Types**: JSONB for flexible metadata storage and arrays for reason lists
- **Migrations**: Drizzle Kit for version-controlled database schema changes

The database schema supports both URL and file scanning with shared result structures, enabling unified reporting and analytics.

## Security and Risk Assessment
The core security engine implements a multi-provider approach:
- **Provider Interface**: Abstracted security check providers for modularity
- **Scoring Algorithm**: Weighted risk scoring from 0-100 based on multiple factors
- **Threat Intelligence**: Integration with Google Safe Browsing, PhishTank, and WHOIS data
- **Heuristic Analysis**: Custom algorithms for domain age, URL patterns, and suspicious characteristics
- **File Analysis**: VirusTotal integration for malware detection (development environment)

Risk assessment combines quantitative scores with qualitative reasons, providing users with both overall risk levels and detailed explanations.

# External Dependencies

## Security Providers
- **Google Safe Browsing**: Web Risk API for known malicious URL detection
- **PhishTank**: Community-driven phishing database for URL reputation
- **VirusTotal**: File scanning and malware detection (development phase)
- **WHOIS/RDAP**: Domain registration and age verification services
- **AbuseIPDB**: IP reputation and geolocation data

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