@echo off
echo Starting DataDefenceX Web Interface...
echo.
echo Starting Backend API...
start "DataDefenceX API" cmd /k "python -m uvicorn api.main:app --reload --host 0.0.0.0 --port 8000"
timeout /t 3 /nobreak >nul
echo.
echo Starting Frontend...
start "DataDefenceX Frontend" cmd /k "cd frontend && npm run dev"
echo.
echo Both servers are starting...
echo Backend: http://localhost:8000
echo Frontend: http://localhost:3000
echo.
pause

