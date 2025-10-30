# How to Export Your Code from Replit

Follow these steps to download your TryggLink project and prepare it for Vercel deployment.

---

## Method 1: Download as ZIP (Easiest)

1. **In your Replit workspace:**
   - Click the **three dots menu** (⋮) in the top-right corner
   - Select **"Download as ZIP"**
   - Save the ZIP file to your computer

2. **Extract the ZIP:**
   - Unzip the downloaded file to a folder (e.g., `TryggLink/`)
   - Remember this location - you'll open it in Cursor

3. **What's included:**
   - All your source code (`client/`, `server/`, `shared/`)
   - Configuration files (`package.json`, `tsconfig.json`, etc.)
   - Migration guide (`VERCEL_MIGRATION.md`)
   - Vercel configuration (`vercel.json`)

---

## Method 2: Git Clone (Recommended for Version Control)

### Enable Git Repository in Replit:

1. **In Replit:**
   - Click the **Version Control** icon (Git branch icon) in the left sidebar
   - If not initialized, click **"Initialize Git repository"**
   - Commit all your changes

2. **Connect to GitHub:**
   - Click **"Create a GitHub repository"** in the Version Control panel
   - Follow the prompts to create a new repo
   - Replit will push your code to GitHub

3. **Clone to Your Computer:**
```bash
# Open terminal on your computer
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>
```

**Benefits of Git:**
- ✅ Easy to sync changes
- ✅ Version history preserved
- ✅ Direct deployment to Vercel from GitHub
- ✅ Easier collaboration

---

## Method 3: Manual File Copy (Not Recommended)

If the above methods don't work, you can manually copy files:

1. In Replit, open each file
2. Copy the content
3. Create the same file on your computer
4. Paste the content

**Note:** This is tedious and error-prone. Use Method 1 or 2 instead.

---

## After Exporting: Next Steps

### 1. Open in Cursor IDE
```bash
# Navigate to your project folder
cd TryggLink/

# Open in Cursor (if installed)
cursor .
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Test Locally (Optional)
```bash
# Run development server
npm run dev
```

### 4. Follow Migration Guide
Open `VERCEL_MIGRATION.md` and follow the step-by-step instructions to:
- Convert Express routes to Vercel serverless functions
- Update authentication
- Configure file uploads
- Deploy to Vercel

---

## ✅ Export Checklist

- [ ] Code downloaded/cloned from Replit
- [ ] Files extracted to a folder
- [ ] Cursor IDE installed
- [ ] Node.js v18+ installed
- [ ] Project folder opened in Cursor
- [ ] Dependencies installed (`npm install`)
- [ ] Ready to follow `VERCEL_MIGRATION.md`

---

## 🆘 Troubleshooting

### "Download as ZIP" option not visible
- Try clicking your username → Account → Download Repl as ZIP
- Or use Git method instead

### Git clone asks for authentication
```bash
# Use HTTPS with personal access token
git clone https://<token>@github.com/<username>/<repo>.git

# Or set up SSH keys
ssh-keygen -t ed25519 -C "your@email.com"
# Add key to GitHub: Settings → SSH and GPG keys
```

### Files missing after export
- Make sure you exported from the correct Replit project
- Check if files are hidden (show hidden files in your file explorer)

---

## 📁 Expected Folder Structure After Export

```
TryggLink/
├── client/                 # React frontend
│   ├── src/
│   └── index.html
├── server/                 # Express backend (will convert to /api)
│   ├── routes.ts
│   ├── index.ts
│   └── lib/
├── shared/                 # Shared types/schemas
│   └── schema.ts
├── package.json
├── vercel.json            # Vercel configuration (updated)
├── VERCEL_MIGRATION.md    # Full migration guide
└── EXPORT_INSTRUCTIONS.md # This file
```

---

**Next:** Once exported, open `VERCEL_MIGRATION.md` to continue the migration process!
