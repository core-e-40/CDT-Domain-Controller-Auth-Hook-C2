param(
    [Parameter(Mandatory=$true)]
    [string]$DllPath
)

# Get just the filename without extension
$DllName = [System.IO.Path]::GetFileNameWithoutExtension($DllPath)
$Dest    = "C:\Windows\System32\$([System.IO.Path]::GetFileName($DllPath))"

Write-Host "DLL Name: $DllName"
Write-Host "Copying $DllPath -> $Dest"

# Copy DLL to System32
Copy-Item -Path $DllPath -Destination $Dest -Force

# Update the Notification Packages registry value
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$Current = (Get-ItemProperty $RegPath)."Notification Packages"

if ($Current -notcontains $DllName) {
    $New = $Current + $DllName
    Set-ItemProperty -Path $RegPath -Name "Notification Packages" -Value $New
    Write-Host "Registry updated: $($New -join ', ')"
} else {
    Write-Host "Registry already contains $DllName, skipping"
}

Write-Host "Done. Reboot for changes to take effect."