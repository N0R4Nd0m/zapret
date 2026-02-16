@echo off
color f0
title SniFinder
pushd "%~dp0"
setlocal enableExtensions enableDelayedExpansion

set asnFile=Asn.csv

:begin
cls

set asn=
set domain=

set /p domain=Enter domain (for example, youtube.com) : 
if not defined domain goto :begin

:: Определяем asn домена
for /f "tokens=* delims=" %%j in ('curl.exe -4ks -m 5 "http://ip-api.com/json/%domain%?fields=as"') do (
	set "json=%%j"
	set "json=!json:{=!"
	set "json=!json:}=!"
	for /f "tokens=1,* delims=:" %%a in ("!json!") do (
		if /i "%%~a"=="as" (
			for /f "tokens=1" %%c in ("%%~b") do set "asn=%%~c"
		)
	)	
)

if not defined asn (
	@echo ERROR: Can't find Asn for %domain%
	pause
	goto :begin
)

@echo ------------------------------------------------------------------------------
@echo Asn: %asn%
@echo ------------------------------------------------------------------------------
:: Ищем белый sni для asn
set i=0
for /f "tokens=1,2 delims=;" %%a in (%asnFile%) do (
	if /i "%%a"=="%asn%" (
		set /a i +=1
		@echo Sni N!i!: %%b
	)
)
if %i%==0 @echo ERROR: Can't find Sni for %domain%
pause
goto :begin