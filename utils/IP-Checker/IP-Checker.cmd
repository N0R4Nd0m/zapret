@echo off
color f0
title %~n0
::------------------------------------------------------------------------------------------------------
:: Глобальные параметры скрипта
set "$scriptDir=%~dp0"
set $scriptFile=%~nx0
set $logFile=%~n0.log
set $filesDir=Files
set $curlDir=%$filesDir%\curl
set $curl=curl-impersonate.exe
set $curlLog=curl.log
set $browserDir=browsers
set $checkListsDir=CheckLists
set $ipCacheFile=IpCache.ini
set $dohFile=%$filesDir%\DoH.txt
set $dnsFile=%$filesDir%\DNS.txt
set $curlDir=%$filesDir%\curl
set $curl=curl-impersonate.exe
set $curlLog=curl.log
set $curlKeys=--ca-native --silent --ipv4
set $browser=chrome142
set $scheme=https
set $timeout=3
set $whiteSni=localhost
set $fakeSni=4pda.to
set $cloudflareIp=172.66.159.63
::------------------------------------------------------------------------------------------------------
setlocal enableExtensions enableDelayedExpansion

pushd "!$scriptDir!"

call :Show Info "===============================================================================================" log
call :Show Info "Проверка запущена в %time:~0,8% %date%" log

:: Смена кодовой страницы cmd на рус. кодировку
call :SetCodePage 866

if not exist "%$curlDir%\%$curl%" call :Show Error "Не найдена утилита %$curlDir%\%$curl%. Убедитесь, что файл не удален антивирусом" log cs

:: Проверка прав
start "curl" /min %$curlDir%\%$curl% -m 3 -o nul https://1.2.3.4
timeout /nobreak /t 1 1>nul 2>&1
tasklist|findstr /ic:"%$curl%" 1>nul 2>&1 && taskkill /t /f /im "%$curl%" 1>nul 2>&1 || call :Show Error "Не удалось завершить процесс %$curl%. %$scriptFile% должен быть запущен с правами админа [правая кнопка мыши на файле - выбрать 'Запуск от имени Администратора']" log cs

:: Проверка фейкового sni:
call :CheckAccessBySni $fakeSni "https://%$fakeSni%"
if not defined $fakeSni.Yes (
	call :Show Error "Через %$curl% не доступен фейковый sni %$fakeSni%. 1.Перезапустите %$scriptFile%; 2.Разрешите все исходящие запросы для %$curl% в фаерволле [антивирусе/брандмауэре] либо отключите последние на время проверки; 3.Проверьте интернет-соединение; 4.Проверьте службу DNS-клиент; Если ничего не помогает, поменяйте значение $fakeSni в %$iniFile% и перезапустите скрипт" log cs
)

::------------------------------------------------------------------------------------------------------
:сheckList
cls
for /f "tokens=*" %%c in ('dir /b "%$checkListsDir%\*.txt"') do set checkLists=!checkLists! %%c
call :GetChoice checkList "%checkLists%" "" "Youtube_Site.txt" "Выберите чеклист [список сайтов для проверки]"

title %~n0 for %checkList%

set url.Count=0
for /f "usebackq tokens=1,* eol=# delims=" %%a in ("%$checkListsDir%\%checkList%") do (
	set /a url.Count +=1	
	set url.!url.Count!=%%a
	set url=%%a
	set url=!url://=!
	for /f "tokens=1,* delims=:" %%b in ("!url!") do (
		if "%%c"=="" (
			set u=%%b
		) else (
			set u=%%c
		)
	)
	for /f "tokens=1,* delims=/" %%d in ("!u!") do set domain.!url.Count!=%%d
)
set /a domain.Count=url.Count

if %url.Count%==0 call :Show Error "В файле чеклиста %$checkListsDir%\%checkList% нет доменов для проверки" log cs

call :Show Info "Чеклист [список доменов для проверки]: %$checkListsDir%\%checkList%" log
::------------------------------------------------------------------------------------------------------
call :Show Info "Проверка доступности доменов с системными dns"
call :LoadSettingsFrom "!$scriptDir!%$ipCacheFile%"
call :CheckAccessByIp domain
for /l %%i in (1,1,%domain.Count%) do (
	if not defined ip[!domain.%%i!] set noAccessList=!domain.%%i! !noAccessList!
)
if not defined noAccessList goto :scriptEnd
call :Show Info "Не доступны по ip домены: [%noAccessList%]" log

call :Show Info "Загрузка списка серверов DNS и DoH"
for %%d in (dns doh) do (
	if exist "!$%%dFile!" (
		for /f "usebackq skip=1 tokens=1 eol=#" %%s in ("!$%%dFile!") do set %%dServers=%%s !%%dServers!
	) else (
		call :Show Warn "Не найден файл со списком серверов %%d !$%%dFile!" log
	)
)

call :CheckAccessBySni dohServers "%dohServers%"
if not defined dohServers.Yes (
	call :Show Warn "Не доступен ни один из серверов DoH [Dns-over-Https]: [%dohServers%]" log
	goto :findIpsByDnsServers
)

call :Show Info "Поиск рабочих IP для [%noAccessList%] с DoH [%dohServers.Yes%]" log
for %%s in (%dohServers.Yes%) do (
	set noAccess=
	for /l %%i in (1,1,%domain.Count%) do (
		if not defined ip[!domain.%%i!] set noAccess=!domain.%%i! !noAccess!
	)
	if not defined noAccess goto :ipsFound
	call :Show Info "Запрос ip для [!noAccess!] от DoH %%s"
	call :CheckAccessByIp domain doh "%%s"
)

:findIpsByDnsServers
call :Show Info "Поиск рабочих IP для [%noAccessList%] с DNS [%dnsServers%]" log
for %%s in (%dnsServers%) do (
	set noAccess=
	for /l %%i in (1,1,%domain.Count%) do (
		if not defined ip[!domain.%%i!] set noAccess=!domain.%%i! !noAccess!
	)
	if not defined noAccess goto :ipsFound
	call :Show Info "Запрос ip для [!noAccess!] от dns %%s"
	call :CheckAccessByIp domain dns "%%s"
)

:ipsNotFound
call :CheckAsn "%noAccess%"
for %%d in (%noAccess%) do (
	if not defined ip[%%d] call :Show Warn "Не найден рабочий ip для домена: %%d" log
)	

:ipsFound
for %%d in (%noAccessList%) do (
	if defined ip[%%d] (
		call :Show Info "Рабочий ip-адрес домена %%d - !ip[%%d]!" log
		@echo.!ip[%%d]! %%d>>"%SystemRoot%\System32\drivers\etc\hosts" && (
			call :Show Info "В файл '%SystemRoot%\System32\drivers\etc\hosts' добавлено перенаправление: !ip[%%d]! %%d" log
			ipconfig /flushdns && call :Show Info "Кеш dns сброшен"	log
		) || (
			call :Show Info "Не хватает прав для запись в файл '%SystemRoot%\System32\drivers\etc\hosts'. Добавьте в него перенаправление: !ip[%%d]! %%d и перезапустите службу DNS-клиент" log
		)
	)	
)
::------------------------------------------------------------------------------------------------------
:scriptEnd
call :Show Info "Проверка завершена. Рабочие ip сохранены в файл: %$ipCacheFile% Лог скрипта: %$logFile%" log
pause
popd
exit
::-------------------------------------------------------------------------------------------------------
::Процедуры и функции скрипта
:Show "тип сообщения: info/warn/error" "текст сообщения" "флаг записи в лог" "флаг очистки экрана"
:: Выводит сообщение на экран/в лог. В случае ошибки завершает скрипт
setLocal
set type=%~1
set text=%~2
set writeToLog=%~3
set clearScreen=%~4
if defined clearScreen cls
@echo ------------------------------------------------------------------------------
@echo %type%: %text%
chcp 1251>nul
if defined writeToLog @echo %type%: %text%.>>"!$scriptDir!%$logFile%"
chcp 866>nul
if /i "%type%"=="warn" pause
if /i "%type%"=="error" pause & exit
endLocal
exit /b

:CheckAsn "список доменов"
:: Проверяет asn доменов
:: Для доменов на CF возвращает $cloudflareIp
setLocal
set domains=%~1
for %%d in (%domains%) do (
	for /f "tokens=* delims=" %%j in ('%$curlDir%\%$curl% -K %$curlDir%\%$browserDir%\%$browser%.txt -4ks -m 3 "http://ip-api.com/json/%%d?fields=as"') do (
		set "json=%%j"
		set "json=!json:{=!"
		set "json=!json:}=!"
		for /f "tokens=1,* delims=:" %%a in ("!json!") do (
			@echo %%~b|findstr /ic:"Cloudflare" && call :SaveSettingTo "!$scriptDir!%$ipCacheFile%" "ip[%%d]" "%$cloudflareIp%"
		)
	)
)
endLocal & (
	call :LoadSettingsFrom "%$scriptDir%%$ipCacheFile%"
)
exit /b

:CheckAccessBySni "имя переменной" "список сайтов"
:: Проверяет доступность сайтов по sni (имени сервера)
:: Возвращает для исходного списка сайтов 2 новых: "имя переменной.Yes" - доступные; "имя переменной.No" - недоступные
setLocal
set sites=%~2
pushd "%$curlDir%"
for %%s in (%sites%) do set checkSites="%%s" --output nul !checkSites!
for /f "tokens=1,* delims=;" %%c in ('%$curl% --insecure --silent --ipv4 --head --max-time 3 --write-out "%%{response_code};%%{url}\n" --parallel --parallel-immediate !checkSites!') do (
	if not "%%c"=="000" (
		set sitesYes=%%d !sitesYes!
	) else (
		set sitesNo=%%d !sitesNo!
	)
)
popd
endLocal & (
	set %~1.Yes=%sitesYes%
	set %~1.No=%sitesNo%
)
exit /b

:CheckAccessByIp "массив доменов" "источник ip: dns/doh" "адрес dns/doh"
:: Проверяет доступность домена по ip; если не отвечает со sni доступного сайта, то недоступен;
:: Возвращает глобальные переменные: ip[домен]=рабочий ip/"" (доступен по ip/недоступен);
:: Массив доменов: array, где аrray.1 - 1-ый элемент; array.Count - размер массива;
:: Источник ip: dns - от заданного dns; doh - от заданного doh. Если не указан адрес - от текущего dns;
setLocal
for /l %%i in (1,1,!%~1.Count!) do set domains=!%~1.%%i! !domains!
set source=%~2
set address=%~3
pushd "%$curlDir%"
if /i "%source%"=="dns" if defined address (
	set flags=--dns-servers %address% --max-time 4
)
if /i "%source%"=="doh" if defined address (
	set flags=--doh-insecure --doh-url "%address%" --max-time 4
)
for %%d in (%domains%) do if exist "curl_%%d.log" del /q /f "curl_%%d.log"
for %%d in (%domains%) do (
	if defined ip[%%d] (
		start /min "checkIp" %$curl% --insecure --silent --ipv4 --head --max-time 3 %flags% --insecure --write-out "%%output{>>"curl_%%d.log"}%%{response_code};%%{remote_ip};%%{scheme}\n" --parallel --parallel-immediate https://%%d --output nul --connect-to %%d::!ip[%%d]!:%$customPort% %%d --output nul --connect-to %%d::!ip[%%d]!:%$customPort% https://%$whiteSni% --output nul --connect-to %$whiteSni%::!ip[%%d]!:%$customPort% %$whiteSni% --output nul --connect-to %$whiteSni%::!ip[%%d]!:%$customPort% https://%$fakeSni% --output nul --connect-to %$fakeSni%::!ip[%%d]!:%$customPort% %$fakeSni% --output nul --connect-to %$fakeSni%::!ip[%%d]!:%$customPort%
	) else (
		start /min "checkDomain" %$curl% --insecure --silent --ipv4 --head --max-time 3 %flags% --insecure --write-out "%%output{>>"curl_%%d.log"}%%{response_code};%%{remote_ip};%%{scheme}\n" --parallel --parallel-immediate https://%%d --output nul %%d --output nul https://%$whiteSni% --output nul --connect-to %$whiteSni%::%%d:%$customPort% %$whiteSni% --output nul --connect-to %$whiteSni%::%%d:%$customPort% https://%$fakeSni% --output nul --connect-to %$fakeSni%::%%d:%$customPort% %$fakeSni% --output nul --connect-to %$fakeSni%::%%d:%$customPort%
	)
)
for /l %%t in (1,1,5) do (
	tasklist|findstr /i /c:"%$curl%" 1>nul 2>&1 && timeout /nobreak /t 1 1>nul 2>&1
)
taskkill /t /f /im "%$curl%" 1>nul 2>&1
for %%d in (%domains%) do (
	set ip[%%d]=
	for /f "usebackq tokens=1,2,* delims=;" %%i in ("curl_%%d.log") do (
		if not "%%i"=="000" set ip[%%d].%%k=%%j
	)
	if defined ip[%%d].https (
		set ip[%%d]=!ip[%%d].https!
	) else (
		if defined ip[%%d].http set ip[%%d]=!ip[%%d].http!
	)
)
for %%d in (%domains%) do if exist "curl_%%d.log" del /q /f "curl_%%d.log"
popd
for %%d in (%domains%) do call :SaveSettingTo "!$scriptDir!%$ipCacheFile%" "ip[%%d]" "!ip[%%d]!"
endLocal & (
	call :LoadSettingsFrom "%$scriptDir%%$ipCacheFile%"
)
exit /b

:SaveSettingTo "файл" "название настройки" "значение" "номер строки для вставки"
:: Сохраняет в файл настройку в формате название_настройки=значение
:: Если настройка уже существует, то ее значение переписывается с сохранением позиции в файле
:: Если не существует, дописывается в заданную позицию файла или в конец
setLocal
set file=%~1
set setting=%~2
set value=%~3
set stringN=%~4
set string=%setting%=%value%
set settingN=
set n=0
if exist "%file%" (
	for /f "usebackq eol=? tokens=* delims=" %%s in ("%file%") do set /a n +=1
	(for /l %%i in (1,1,!n!) do set /p string.%%i=)<"%file%"
)
for /f "tokens=1 delims=:" %%n in ('findstr /inbc:"%setting%=" "%file%" 2^>nul') do set /a settingN=%%n
if defined settingN (
	if /i "!string.%settingN%!"=="%string%" goto :saveSetting_end
	set string.%settingN%=%string%
) else (
	if not defined stringN set /a stringN=n + 1
	for /l %%i in (%n%,-1,!stringN!) do (
		set /a j=%%i + 1
		set "string.!j!=!string.%%i!"
	)
	set string.!stringN!=%string%
	set /a n +=1
)
(for /l %%i in (1,1,%n%) do @echo !string.%%i!)>"%file%"
:saveSetting_end
endLocal
exit /b

:LoadSettingsFrom "файл"
:: Загружает настройки из файла (в формате название_настройки=значение). Символ # считается комментарием 
if exist "%~1" for /f "usebackq tokens=1,* delims== eol=#" %%i in ("%~1") do set "%%i=%%j"
exit /b

:GetChoice "имя переменной" "список значений" "список наименований" "значение по умолчанию" "текст"
:: Возвращает значение, выбранное из списка (плюс его наименование и номер выбранного пункта)
:: Если значения/наименования содержат пробелы, при вызове их нужно заключать в ''
setLocal
set values=%~2
set valueNames=%~3
set valueDef=%~4
set text=%~5
if not defined values call :Show Error "Не задан список значений для выбора %~1" log
set values=!values:'="!
if defined valueNames (
	set valueNames=!valueNames:'="!
	set count=0 
	for %%j in (!valueNames!) do (
		set /a count +=1
		set valueName.!count!=%%~j
	)
)
set count=0
for %%i in (%values%) do (
     set /a count +=1
	 if /i "%%~i"=="%valueDef%" set /a valueN=count
	 set value.!count!=%%~i
)
@echo %text%	 
for /l %%n in (1,1,%count%)	do (
	if defined valueName.%%n (
		@echo %%n. !valueName.%%n! [!value.%%n!]
	) else (
		@echo %%n. !value.%%n!
	)
)
if not defined valueN set valueN=1
:choiceLoop
set choiceN=%valueN%
set /p choiceN=Нажмите номер выбранного пункта (по умолчанию %valueN% [!value.%valueN%!]) и клавишу Enter: 
set result=!value.%choiceN%!
set resultName=!valueName.%choiceN%!
if not defined result (
	@echo ОШИБКА: Номер выбранного пункта %choiceN% вне диапазона от 1 до %count%
	goto :choiceLoop
)
endLocal & (
    set %~1=%result%
	set %~1.Name=%resultName%
	set %~1.N=%choiceN%
)
exit /b

:SetCodePage "кодовая страница: 866/1251/65001"
:: Устанавливает рус. кодировку командной строки (должна совпадать с кодировкой скрипта)
setLocal
set CodePage=%~1
set FaceName="Lucida Console"
set FontFamily=0x0000036
set FontWeight=0x0000190
set FontSize=0x000d0000
set CodePage.Type=REG_DWORD
set FaceName.Type=REG_SZ
set FontFamily.Type=REG_DWORD
set FontWeight.Type=REG_DWORD
set FontSize.Type=REG_DWORD
set regKey=HKEY_CURRENT_USER\Console\%%SystemRoot%%_system32_cmd.exe
set cp866=0x362
set cp1251=0x4e3
set cp65001=0xfde9
@echo 866 1251 65001|findstr /v %CodePage% 1>nul 2>&1 && call :Show Error "Code page must be 866/1251/65001" log
for /f "eol= tokens=3*" %%c in ('reg query %%regKey%% /v "CodePage" 2^>nul') do set cmdCodePage16=%%c
if defined cmdCodePage16 call :Show Info "Для русской локализации скрипта в реестр добавлена ветка %%regKey%%" log
if "%cmdCodePage16%"=="!cp%CodePage%!" endLocal & exit /b
for /f "tokens=1,* delims=:" %%i in ('chcp') do set cmdCodePage=%%~j
cls
if %cmdCodePage%0==%CodePage%0 endLocal & exit /b
for %%p in (CodePage FaceName FontFamily FontWeight FontSize) do reg add %regKey% /v %%p /t !%%p.Type! /d !%%p! /f 1>nul 2>&1 || call :Show Error "%$scriptFile% must be run from Administrator name"
@echo Restarting %$scriptFile% for russian localization
pause
start cmd /k "%$scriptFile%"
exit