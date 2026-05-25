@echo off
chcp 65001 >nul
title ReconARG Diagnostico - Lanzador Portable
color 0B

echo ================================================================
echo                  RECONARG DIAGNOSTICO
echo              Lanzador Portable v4.0
echo ================================================================
echo.

REM === Detectar carpeta del .bat (pendrive) ===
set "ORIGEN=%~dp0"
set "EXE_ORIGEN=%ORIGEN%reconarg-diagnostico-win.exe"

REM === Carpeta local de trabajo (disco local, no el pendrive) ===
set "DESTINO=%LOCALAPPDATA%\ReconARG"
set "EXE_DESTINO=%DESTINO%\reconarg-diagnostico-win.exe"

if not exist "%EXE_ORIGEN%" (
    echo [ERROR] No se encuentra reconarg-diagnostico-win.exe junto a este .bat
    echo         Ruta esperada: %EXE_ORIGEN%
    pause
    exit /b 1
)

echo [1/5] Preparando carpeta local...
if not exist "%DESTINO%" mkdir "%DESTINO%" >nul 2>&1

echo [2/5] Copiando ejecutable al disco local...
copy /Y "%EXE_ORIGEN%" "%EXE_DESTINO%" >nul
if errorlevel 1 (
    echo [ERROR] No se pudo copiar el ejecutable.
    echo         Intenta ejecutar como Administrador.
    pause
    exit /b 1
)

echo [3/5] Quitando marca de internet (Mark-of-the-Web)...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Unblock-File -Path '%EXE_DESTINO%' -ErrorAction SilentlyContinue" >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Remove-Item -Path '%EXE_DESTINO%:Zone.Identifier' -Force -ErrorAction SilentlyContinue } catch {}" >nul 2>&1

echo [4/5] Configurando exclusion de Windows Defender...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command Add-MpPreference -ExclusionPath \"'%DESTINO%'\" -ErrorAction SilentlyContinue; Add-MpPreference -ExclusionProcess \"reconarg-diagnostico-win.exe\" -ErrorAction SilentlyContinue' -WindowStyle Hidden -ErrorAction SilentlyContinue" >nul 2>&1

echo [5/5] Iniciando ReconARG...
echo.
echo ----------------------------------------------------------------
echo  Si Windows SmartScreen aparece (pantalla azul):
echo    1) Clic en "Mas informacion"
echo    2) Clic en "Ejecutar de todas formas"
echo ----------------------------------------------------------------
echo.
echo Abriendo navegador en http://localhost:3737 en 5 segundos...
echo Para cerrar el servidor: cierra esta ventana negra.
echo.

start "" "%EXE_DESTINO%"
timeout /t 5 /nobreak >nul
start "" "http://localhost:3737"

echo.
echo ReconARG corriendo. NO cierres esta ventana mientras lo uses.
echo ================================================================
pause >nul
