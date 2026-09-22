@echo off
title PuzzleRadar Go Worker - Puzzle #71
set HUB_URL=https://puzzleradar-production.up.railway.app
set WORKER_NAME=%COMPUTERNAME%-%USERNAME%
set LANES=1024
echo Escolha a potencia de CPU:
echo [1] 50%% (Recomendado para usar o PC normalmente)
echo [2] 100%% (Potencia Maxima)
set /p pot="Opcao (1 ou 2): "
if "%%pot%%"=="1" set CPU_FLAG=--cpu 50
if "%%pot%%"=="2" set CPU_FLAG=--cpu 100
worker.exe %%CPU_FLAG%%
pause