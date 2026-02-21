@echo off
color f0
title DoHChecker
setlocal enableExtensions enableDelayedExpansion

set dohFile=DoH.txt
set sni=localhost
set domains=rutracker.org

set i=0
for %%d in (%domains%) do (	
	@echo   				DOMAIN =%%d :
	for /f "usebackq skip=1 tokens=1 eol=#" %%s in ("%dohFile%") do (
		set /a i +=1
		@echo   		   DoH!i! =%%s :
		"curl\curl-impersonate.exe" --ipv4 --insecure --silent --max-time 4 --doh-insecure --doh-url "%%s" --write-out "IP=%%{remote_ip}\nTime=%%{time_total}\n" --parallel --parallel-immediate https://%sni% --output nul --connect-to %sni%::%%d %sni% --output nul --connect-to %sni%::%%d
		@echo.------------------
		pause
	)
	@echo.------------------------------------------------------------------------
)

pause
