@echo off
setlocal
set "ROOT=%~dp0"
cd /d "%ROOT%"

start "MCP Security Gateway" /D "%ROOT%" cmd /k node -r ts-node/register src/proxy/server.ts

echo Started MCP Security Gateway on http://127.0.0.1:3000
echo.
echo Open dashboard: http://localhost:3000/dashboard
endlocal
