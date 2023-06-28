@echo off

cd %~dp0

.\Third-party\MinSudo.exe --NoLogo --Privileged powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& {Start-Process powershell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File "".\Nuke_Microsoft_Edge.ps1""' -Verb RunAs}"
