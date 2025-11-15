# DataDefenceX Deployment Guide

This guide covers deploying the DataDefenceX web interface to Vercel with the backend running locally via ngrok.

## Prerequisites

- GitHub account
- Vercel account (free tier works)
- ngrok account (free tier works)
- Node.js and npm installed
- Python 3.8+ installed
- All project dependencies installed

## Step 1: Prepare Your Repository

1. **Ensure all files are committed and pushed to GitHub:**
   ```bash
   git add .
   git commit -m "Prepare for deployment"
   git push origin main
   ```

## Step 2: Set Up ngrok for Backend

### 2.1 Install ngrok

1. Go to [ngrok.com](https://ngrok.com) and sign up for a free account
2. Download ngrok for Windows
3. Extract ngrok.exe to a folder (e.g., `C:\ngrok`)
4. Add ngrok to your PATH or note the full path

### 2.2 Get Your ngrok Auth Token

1. After signing up, go to [ngrok dashboard](https://dashboard.ngrok.com/get-started/your-authtoken)
2. Copy your authtoken
3. Configure ngrok:
   ```bash
   ngrok config add-authtoken YOUR_AUTH_TOKEN
   ```

### 2.3 Start Your Backend

1. Open a terminal and navigate to your project:
   ```bash
   cd C:\Users\djsol\Desktop\DataDefence
   ```

2. Activate your virtual environment:
   ```bash
   .\venv\Scripts\activate
   ```

3. Start the backend server:
   ```bash
   python -m uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
   ```

   Keep this terminal open - the backend must stay running.

### 2.4 Expose Backend with ngrok

1. Open a **new terminal window**
2. Run ngrok to expose port 8000:
   ```bash
   ngrok http 8000
   ```

3. You'll see output like:
   ```
   Forwarding   https://abc123.ngrok-free.app -> http://localhost:8000
   ```

4. **Copy the HTTPS URL** (e.g., `https://abc123.ngrok-free.app`)
   - This is your backend URL
   - Note: Free ngrok URLs change each time you restart ngrok
   - For production, consider ngrok paid plan for static domains

5. **Important:** Keep both terminals open:
   - Terminal 1: Backend server running
   - Terminal 2: ngrok tunnel running

## Step 3: Deploy Frontend to Vercel

### 3.1 Connect GitHub to Vercel

1. Go to [vercel.com](https://vercel.com) and sign in
2. Click "Add New Project"
3. Import your GitHub repository
4. Select the repository containing DataDefenceX

### 3.2 Configure Vercel Project

1. **Root Directory:** Set to `frontend`
   - Click "Edit" next to Root Directory
   - Enter: `frontend`

2. **Framework Preset:** Vite (should auto-detect)

3. **Build Command:** `npm run build` (should be auto-filled)

4. **Output Directory:** `dist` (should be auto-filled)

5. **Install Command:** `npm install` (should be auto-filled)

### 3.3 Set Environment Variables

1. In the Vercel project settings, go to "Environment Variables"
2. Add a new variable:
   - **Name:** `VITE_API_URL`
   - **Value:** `https://YOUR_NGROK_URL.ngrok-free.app/api`
     - Replace `YOUR_NGROK_URL` with your actual ngrok URL from Step 2.4
     - **Important:** Include `/api` at the end
   - **Environment:** Production, Preview, Development (select all)

3. Click "Save"

### 3.4 Deploy

1. Click "Deploy"
2. Wait for the build to complete (usually 1-2 minutes)
3. Once deployed, you'll get a Vercel URL (e.g., `https://datadefencex.vercel.app`)

### 3.5 Update Backend CORS (if needed)

If you get CORS errors, update the backend:

1. Set environment variable before starting backend:
   ```bash
   set FRONTEND_URL=https://your-vercel-url.vercel.app
   ```

2. Or edit `api/main.py` and add your Vercel URL to the CORS origins list

3. Restart the backend server

## Step 4: Test Your Deployment

1. **Open your Vercel URL** in a browser
2. **Check the Dashboard:**
   - You should see the DataDefenceX interface
   - Click "Start Monitoring" to test backend connection
3. **Test Process Monitoring:**
   - Go to Processes page
   - You should see running processes
4. **Test Threat Detection:**
   - Run a suspicious PowerShell command in a new terminal:
     ```powershell
     powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAVABlAHMAdAAgAEQAZQB0AGUAYwB0AGkAbwBuACIA
     ```
   - Check the Detections page - it should appear

## Step 5: Update ngrok URL (When It Changes)

**Important:** Free ngrok URLs change when you restart ngrok. To update:

1. Get your new ngrok URL
2. Go to Vercel Dashboard → Your Project → Settings → Environment Variables
3. Update `VITE_API_URL` with the new ngrok URL
4. Redeploy (Vercel will auto-redeploy, or click "Redeploy")

## Troubleshooting

### CORS Errors

**Symptom:** Browser console shows CORS errors

**Solution:**
1. Check that your Vercel URL is in the backend CORS origins
2. Set `FRONTEND_URL` environment variable in backend
3. Restart backend server

### Backend Connection Failed

**Symptom:** Frontend can't connect to backend

**Solution:**
1. Verify ngrok is running and forwarding correctly
2. Check that backend is running on port 8000
3. Verify `VITE_API_URL` in Vercel matches your ngrok URL (with `/api`)
4. Check ngrok dashboard for connection status

### Environment Variable Not Working

**Symptom:** Frontend still uses `/api` instead of ngrok URL

**Solution:**
1. Vite environment variables must start with `VITE_`
2. After adding env var in Vercel, you must redeploy
3. Check browser console for the actual API URL being used

### ngrok URL Changes

**Symptom:** Deployment stops working after restarting ngrok

**Solution:**
1. Get new ngrok URL
2. Update `VITE_API_URL` in Vercel
3. Redeploy frontend

## Production Considerations

For a hackathon demo, the free setup works. For production:

1. **Static ngrok Domain:** Upgrade to ngrok paid plan for a static domain
2. **Backend Hosting:** Consider deploying backend to:
   - Azure Windows VM
   - AWS EC2 Windows instance
   - Railway (if they support Windows)
3. **Custom Domain:** Add custom domain to Vercel
4. **HTTPS:** Both Vercel and ngrok provide HTTPS automatically

## Quick Reference

### Starting Everything Locally (for testing)

1. **Terminal 1 - Backend:**
   ```bash
   cd C:\Users\djsol\Desktop\DataDefence
   .\venv\Scripts\activate
   python -m uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
   ```

2. **Terminal 2 - ngrok:**
   ```bash
   ngrok http 8000
   ```

3. **Terminal 3 - Frontend (optional, for local testing):**
   ```bash
   cd frontend
   npm run dev
   ```

### Environment Variables Summary

**Vercel (Frontend):**
- `VITE_API_URL`: `https://your-ngrok-url.ngrok-free.app/api`

**Backend (Optional):**
- `FRONTEND_URL`: `https://your-vercel-url.vercel.app`
- `NGROK_URL`: `https://your-ngrok-url.ngrok-free.app`

## Support

If you encounter issues:
1. Check browser console for errors
2. Check backend terminal for errors
3. Check ngrok dashboard for connection status
4. Verify all environment variables are set correctly

Good luck with your hackathon! 🚀

