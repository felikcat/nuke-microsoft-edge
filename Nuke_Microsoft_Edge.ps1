#Requires -Version 5 -RunAsAdministrator

Stop-Process -Force -Name "msedge"

# The optimistic approach laid out by Microsoft. Doesn't always work.
& "C:\Program Files (x86)\Microsoft\Edge\Application\*\Installer\setup.exe" --uninstall --system-level --force-uninstall | Out-Null

# https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update
Get-AppxProvisionedPackage -Online '*Microsoft.MicrosoftEdge' | Remove-AppxProvisionedPackage -Online

# Microsoft's Publisher ID.
$ID="8wekyb3d8bbwe"

$PATH = @("C:\Program Files (x86)\Microsoft\Edge\Application",
"$env:windir\SystemApps\Microsoft.MicrosoftEdge_$ID",
"$env:windir\SystemApps\Microsoft.MicrosoftEdgeDevToolsClient_$ID",
"$env:ProgramData\Microsoft\Windows\AppRepository\Packages\Microsoft.MicrosoftEdge*$ID")
$PATH.ForEach({
    $acl = Get-Acl -Path $_
    $accessrule = New-Object System.Security.AccessControl.FileSystemAccessRule ('Everyone', 'FullControl', 'ContainerInherit, ObjectInherit', 'InheritOnly', 'Allow')
    $acl.SetAccessRule($accessrule)
    Set-Acl -Path $_ -AclObject $acl

    Remove-Item -Recurse $_
})

$SERVICES = @("edgeupdate", "edgeupdatem", "MicrosoftEdgeElevationService")
$SERVICES.ForEach({
    sc.exe delete $_
})

$DIRS = @("$env:localappdata\Microsoft\Edge",
"$env:localappdata\Microsoft\WindowsApps\Microsoft.MicrosoftEdge_$ID",
"$env:localappdata\Packages\Microsoft.MicrosoftEdge_$ID",
"$env:localappdata\Packages\Microsoft.MicrosoftEdgeDevToolsClient_$ID",
"$env:ProgramData\Packages\Microsoft.MicrosoftEdge.Stable_$ID",
"$env:ProgramData\Microsoft\Windows\AppRepository\Packages\Microsoft.MicrosoftEdge*$ID")
$DIRS.ForEach({
    Remove-Item -Recurse $_
})

$FILES = @("$env:localappdata\Microsoft\WindowsApps\MicrosoftEdge.exe",
"$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk",
"$env:AppData\Microsoft\Internet Explorer\Quick Launch\Microsoft Edge.lnk",
"$env:AppData\Microsoft\Internet Explorer\Quick Launch\User Pinned\Taskbar\Microsoft Edge.lnk",
"$env:PUBLIC\Desktop\Microsoft Edge.lnk",
"$env:windir\Prefetch\MICROSOFTEDGE*.pf",
"$env:windir\Prefetch\Op-MSEDGE*.pf")
$FILES.ForEach({
    Remove-Item $_
})

$REGS = @("HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge")
$REGS.ForEach({
    Remove-Item -Path $_ -Recurse -Force
})
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store" -Name "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -Force

Unregister-ScheduledTask -TaskPath "\" -TaskName "MicrosoftEdgeUpdateTaskMachineCore" -Confirm:$false
Unregister-ScheduledTask -TaskPath "\" -TaskName "MicrosoftEdgeUpdateTaskMachineUA" -Confirm:$false
