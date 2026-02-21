@echo off
color f0
title DnsChecker

set domains=telegram.org
set dnsFile=DNS.txt

for %%d in (%domains%) do (
	@echo   			DOMAIN =%%d :
	for /f "usebackq skip=1 tokens=1" %%s in ("%dnsFile%") do (
		@echo			   DNS =%%s :
		for /f "skip=4 tokens=1,* delims=: " %%i in ('nslookup -vc -type^=A -timeout^=3 %%~d. %%s 2^>nul') do (
			@echo.%%j|findstr /r /c:"\<[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\>" 1>nul 2>&1 && @echo.IP=%%j
		)
		@echo.------------------
	)
	@echo.--------------------------------------------------------------
)

pause