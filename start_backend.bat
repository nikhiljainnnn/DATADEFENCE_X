@echo off
echo Starting DataDefenceX API Server...
cd /d %~dp0
python -m uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
pause

