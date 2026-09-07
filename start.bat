@echo off
cd /d "%~dp0"
if "%JWT_SECRET%"=="" set JWT_SECRET=SkillBridge-Demo-Secret-2026-At-Least-32-Chars-Long
node backend\server.js
pause
