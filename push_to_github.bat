@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ====================================================================
echo  🛡️ CVE Security Operations Suite — GitHub Repository Synchronizer
echo  Target: https://github.com/anon-wu/CVE_Checker_Anon_X.git
echo ====================================================================
echo.
echo [1/2] Verifying Git Status & Remote...
git status
echo.
echo [2/2] Pushing commits to GitHub (origin/main)...
echo (※ 브라우저 OAuth 로그인 창이 뜨면 Google 로그인을 완료해주세요.)
echo.
git push -u origin main
echo.
if %errorlevel% equ 0 (
    echo [✔] GitHub 동기화가 성공적으로 완료되었습니다!
) else (
    echo [!] 오류가 발생했습니다. 브라우저 인증 또는 토큰을 확인해주세요.
)
echo.
pause
