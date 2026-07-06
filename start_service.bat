@echo off
chcp 65001 >nul
title 钓鱼邮件检测服务 - localhost:8899

echo ============================================
echo   钓鱼邮件检测服务启动中...
echo ============================================

start "PhishGuard 服务" cmd /k "cd /d "%~dp0" && python -m uvicorn app:app --host 0.0.0.0 --port 8899"

if %errorlevel% neq 0 (
    echo.
    echo [!] 服务启动失败，请检查 Python 环境和依赖包
    pause
)
