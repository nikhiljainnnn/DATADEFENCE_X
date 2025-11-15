@echo off
echo Starting DataDefenceX Frontend...
cd /d %~dp0\frontend
call npm run dev
pause

