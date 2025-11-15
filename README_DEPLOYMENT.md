# Quick Deployment Checklist

## Before Deployment

- [ ] All code committed and pushed to GitHub
- [ ] Backend dependencies installed (`pip install -r requirements.txt`)
- [ ] Frontend dependencies installed (`cd frontend && npm install`)

## Deployment Steps

1. **Start Backend Locally:**
   ```bash
   python -m uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
   ```

2. **Start ngrok:**
   ```bash
   ngrok http 8000
   ```
   Copy the HTTPS URL (e.g., `https://abc123.ngrok-free.app`)

3. **Deploy to Vercel:**
   - Go to vercel.com
   - Import GitHub repository
   - Set Root Directory to `frontend`
   - Add Environment Variable:
     - Name: `VITE_API_URL`
     - Value: `https://YOUR_NGROK_URL.ngrok-free.app/api`
   - Deploy

4. **Update Backend CORS (if needed):**
   - Set `FRONTEND_URL` environment variable to your Vercel URL
   - Or manually add Vercel URL to CORS in `api/main.py`

5. **Test:**
   - Open Vercel URL
   - Click "Start Monitoring"
   - Check if processes are loading

## Important Notes

- ngrok free URLs change on restart - update Vercel env var when they change
- Keep backend and ngrok running during demo
- For static URL, consider ngrok paid plan

See `DEPLOYMENT.md` for detailed instructions.

