#Requires -Version 5 -RunAsAdministrator

Stop-Process -Force -Name "msedge"

New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT"
$MSEDGE = (Get-AppxPackage Microsoft.MicrosoftEdge.Stable).PackageFullName

# https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update
Get-AppxProvisionedPackage -Online '*Microsoft.MicrosoftEdge' | Remove-AppxProvisionedPackage -Online

Dism.exe /Online /Remove-ProvisionedAppxPackage /PackageName:$MSEDGE

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

# Using sc.exe is avoided as it can deny disabling these services.
$SERVICES = @("HKLM:\SYSTEM\CurrentControlSet\Services\edgeupdate",
"HKLM:\SYSTEM\CurrentControlSet\Services\edgeupdatem",
"HKLM:\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService")
$SERVICES.ForEach({
    Set-ItemProperty -Path $_ -Name "Start" -Type DWord -Value 4 -Force
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

$REG_DIRS = @("HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge",
"HKLM:\SOFTWARE\Classes\MSEdgeHTM",
"HKLM:\SOFTWARE\Classes\MSEdgeMHT",
"HKLM:\SOFTWARE\Classes\MSEdgePDF",
"HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.MicrosoftEdge.Stable_$ID",
"HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\Edge")
$REG_DIRS.ForEach({
    Remove-Item -Path $_ -Recurse -Force
})

# Hard-coded way of removing file associations; done to not take ages.
Remove-ItemProperty "HKCR:\.htm\OpenWithProgids" -Name "MSEdgeHTM"
Remove-ItemProperty "HKCR:\.html\OpenWithProgids" -Name "MSEdgeHTM"
Remove-ItemProperty "HKCR:\.shtml\OpenWithProgids" -Name "MSEdgeHTM"
Remove-ItemProperty "HKCR:\.svg\OpenWithProgids" -Name "MSEdgeHTM"
Remove-ItemProperty "HKCR:\.webp\OpenWithProgids" -Name "MSEdgeHTM"
Remove-ItemProperty "HKCR:\.xht\OpenWithProgids" -Name "MSEdgeHTM"
Remove-ItemProperty "HKCR:\.xhtml\OpenWithProgids" -Name "MSEdgeHTM"

Remove-ItemProperty "HKCR:\.mht\OpenWithProgids" -Name "MSEdgeMHT"
Remove-ItemProperty "HKCR:\.mhtml\OpenWithProgids" -Name "MSEdgeMHT"

Remove-ItemProperty "HKCR:\.pdf\OpenWithProgids" -Name "MSEdgePDF"


Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store" -Name "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -Force

Unregister-ScheduledTask -TaskPath "\" -TaskName "MicrosoftEdgeUpdateTaskMachineCore" -Confirm:$false
Unregister-ScheduledTask -TaskPath "\" -TaskName "MicrosoftEdgeUpdateTaskMachineUA" -Confirm:$false
