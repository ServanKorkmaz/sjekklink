# TryggLink Migration Guide: Replit → Vercel

This guide will help you migrate your TryggLink security scanner from Replit to Vercel using serverless functions.

## 📋 Prerequisites

- **Cursor IDE** installed on your computer
- **Node.js** v18+ installed
- **Vercel account** (free tier works)
- **GitHub account** (recommended for deployment)
- **Domain access** (sjekk.no DNS settings)

---

## Step 1: Export Code from Replit

### Option A: Download ZIP
1. In Replit, click the **three dots** (⋮) menu
2. Select **Download as ZIP**
3. Extract the ZIP file to a folder on your computer

### Option B: Clone Git Repository (Recommended)
```bash
# In your terminal:
git clone <your-replit-git-url>
cd <project-folder>
```

---

## Step 2: Open in Cursor

1. Open **Cursor IDE**
2. File → Open Folder
3. Select your extracted/cloned TryggLink folder
4. Install dependencies:
```bash
npm install
```

---

## Step 3: Restructure for Vercel Serverless

The main change: Express routes become serverless API functions.

### Current Structure (Replit):
```
server/
  ├── routes.ts          (Express routes)
  ├── index.ts           (Express server)
  └── lib/
```

### New Structure (Vercel):
```
api/                     (NEW - Serverless functions)
  ├── scan-url.ts
  ├── scan-file.ts
  ├── scans.ts
  ├── admin/
  │   ├── stats.ts
  │   └── recent-scans.ts
  ├── auth/
  │   ├── user.ts
  │   ├── login.ts
  │   ├── logout.ts
  │   └── callback.ts
  └── _lib/              (Shared utilities)
      ├── virustotal.ts
      ├── score.ts
      └── db.ts
```

---

## Step 4: Convert Routes to Serverless Functions

Each Vercel serverless function exports a handler:

### Example: URL Scanning
**File: `api/scan-url.ts`**
```typescript
import type { VercelRequest, VercelResponse } from '@vercel/node';
import { scanUrl } from './_lib/scanner';

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
) {
  if (req.method !== 'POST') {
    return res.status(405).json({ message: 'Method not allowed' });
  }

  try {
    const { url } = req.body;
    const result = await scanUrl(url);
    return res.status(200).json(result);
  } catch (error) {
    return res.status(500).json({ message: 'Scan failed' });
  }
}
```

### Key Changes:
- ✅ Export `default async function handler`
- ✅ Use `VercelRequest` and `VercelResponse` types
- ✅ Each file = one API endpoint
- ✅ File path = API route (e.g., `api/scan-url.ts` → `/api/scan-url`)

---

## Step 5: Handle File Uploads with Vercel Blob

Vercel's serverless has 4.5MB request limit. For file uploads, use **Vercel Blob Storage**.

### Install Vercel Blob:
```bash
npm install @vercel/blob
```

### Update File Scanner:
**File: `api/scan-file.ts`**
```typescript
import { put } from '@vercel/blob';
import type { VercelRequest, VercelResponse } from '@vercel/node';

export const config = {
  api: {
    bodyParser: {
      sizeLimit: '32mb',
    },
  },
};

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
) {
  // Upload to Vercel Blob
  const blob = await put('scan-file.tmp', req.body, {
    access: 'public',
  });
  
  // Scan the file
  const result = await scanFileFromUrl(blob.url);
  
  return res.json(result);
}
```

---

## Step 6: Update Authentication

### Replit Auth → Vercel
Update redirect URLs in your Replit Auth settings:

**Old (Replit):**
```
https://your-app.replit.app/api/callback
```

**New (Vercel):**
```
https://sjekk.no/api/auth/callback
```

### Update Environment Variables:
```bash
# In Vercel dashboard or CLI
ISSUER_URL=<replit-auth-issuer>
CLIENT_ID=<replit-client-id>
CLIENT_SECRET=<replit-client-secret>
```

---

## Step 7: Verify vercel.json Configuration

The `vercel.json` file has already been configured for you with the correct settings:

```json
{
  "version": 2,
  "buildCommand": "npm run build",
  "outputDirectory": "dist/public",
  "rewrites": [
    {
      "source": "/api/:path*",
      "destination": "/api/:path*"
    },
    {
      "source": "/(.*)",
      "destination": "/index.html"
    }
  ],
  "functions": {
    "api/**/*.ts": {
      "runtime": "@vercel/node@3.0.0",
      "maxDuration": 30
    }
  },
  "env": {
    "NODE_ENV": "production"
  }
}
```

**Key settings:**
- `buildCommand`: Uses `npm run build` (runs Vite build for frontend)
- `outputDirectory`: Frontend builds to `dist/public`
- `rewrites`: Routes `/api/*` to serverless functions, everything else to React app
- `maxDuration`: 30 seconds for API functions (enough for VirusTotal scanning)

---

## Step 8: Update package.json Scripts (After API Conversion)

After you've converted your Express routes to serverless functions (Step 3), update your build script:

**Current (Replit - Express server):**
```json
{
  "scripts": {
    "build": "vite build && esbuild server/index.ts ..."
  }
}
```

**New (Vercel - Serverless):**
```json
{
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  }
}
```

**Why the change?**
- ✅ Vercel doesn't need server bundling (esbuild) - API routes are serverless
- ✅ Only frontend (Vite) needs to be built
- ✅ Simpler, faster builds

---

## Step 9: Set Environment Variables on Vercel

### Required Variables:
```bash
DATABASE_URL=<neon-postgres-connection-string>
VIRUSTOTAL_API_KEY=<your-virustotal-key>
SESSION_SECRET=<random-secret-string>
ISSUER_URL=<replit-auth-issuer>
CLIENT_ID=<replit-client-id>
CLIENT_SECRET=<replit-client-secret>
```

### How to Add:
1. Go to Vercel Dashboard → Your Project
2. Settings → Environment Variables
3. Add each variable above
4. Make sure to select **Production**, **Preview**, and **Development**

---

## Step 10: Deploy to Vercel

### Option A: Deploy via Vercel Dashboard (Easiest)
1. Go to https://vercel.com/new
2. Import your GitHub repository
3. Vercel auto-detects settings
4. Click **Deploy**

### Option B: Deploy via Vercel CLI
```bash
# Install Vercel CLI
npm i -g vercel

# Login
vercel login

# Deploy
vercel --prod
```

---

## Step 11: Configure Custom Domain (sjekk.no)

### In Vercel Dashboard:
1. Go to **Project Settings** → **Domains**
2. Click **Add Domain**
3. Enter: `sjekk.no`
4. Vercel will provide DNS records

### Update DNS at Your Registrar:
**A Record:**
- Name: `@`
- Value: `76.76.21.21` (Vercel's IP)

**CNAME Record (for www):**
- Name: `www`
- Value: `cname.vercel-dns.com`

### SSL Certificate:
- ✅ Vercel automatically generates SSL certificate
- ✅ No manual configuration needed
- ✅ "Not Secure" warning disappears automatically

---

## Step 12: Test Everything

After deployment, test:

✅ **URL Scanning:** https://sjekk.no → Test URL scan
✅ **File Scanning:** Upload a test file
✅ **Authentication:** Login/logout functionality
✅ **Admin Dashboard:** https://sjekk.no/admin
✅ **SSL Certificate:** Check for HTTPS padlock icon

---

## 🎯 Migration Checklist

- [ ] Code exported from Replit
- [ ] Project opened in Cursor
- [ ] Dependencies installed (`npm install`)
- [ ] Backend routes converted to `/api` folder
- [ ] File upload using Vercel Blob
- [ ] `vercel.json` updated
- [ ] Environment variables set on Vercel
- [ ] Deployed to Vercel
- [ ] Custom domain (sjekk.no) configured
- [ ] DNS records updated
- [ ] SSL certificate working
- [ ] All features tested

---

## ⚠️ Common Issues

### Issue: "Module not found" errors
**Solution:** Make sure all imports use absolute paths or Vercel aliases:
```typescript
// Bad
import { db } from '../../server/db';

// Good
import { db } from '@/lib/db';
```

### Issue: File upload fails
**Solution:** Ensure Vercel Blob is configured and size limits are set:
```typescript
export const config = {
  api: { bodyParser: { sizeLimit: '32mb' } }
};
```

### Issue: Session not persisting
**Solution:** Use PostgreSQL-backed sessions (not in-memory):
```typescript
import connectPgSimple from 'connect-pg-simple';
const PgSession = connectPgSimple(session);
```

---

## 📚 Resources

- [Vercel Serverless Functions Docs](https://vercel.com/docs/functions/serverless-functions)
- [Vercel Blob Storage](https://vercel.com/docs/storage/vercel-blob)
- [Vercel Environment Variables](https://vercel.com/docs/projects/environment-variables)
- [Neon PostgreSQL with Vercel](https://neon.tech/docs/guides/vercel)

---

## 🚀 Next Steps After Migration

1. **Set up monitoring:** Add Vercel Analytics
2. **Enable caching:** Configure edge caching for faster performance
3. **Add rate limiting:** Use Vercel Edge Middleware
4. **Optimize images:** Use Vercel Image Optimization

---

**Questions?** Check the troubleshooting section or refer to Vercel documentation.

Good luck with your migration! 🎉
