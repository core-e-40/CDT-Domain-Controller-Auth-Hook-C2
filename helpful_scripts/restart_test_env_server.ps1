# This tells Windows to replace the file at next boot before any locks
$source = "C:\Windows\System32\cory_filter_new.dll"
$dest   = "C:\Windows\System32\cory_filter.dll"

# First copy new DLL with temp name (no lock)
Copy-Item ".\cory_filter.dll" $source

# Schedule the swap at boot
$sig = @"
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
"@
$type = Add-Type -MemberDefinition $sig -Name "MoveFileEx" -Namespace Win32 -PassThru
$type::MoveFileEx($source, $dest, 0x5)  # MOVEFILE_REPLACE_EXISTING | MOVEFILE_DELAY_UNTIL_REBOOT

Restart-Computer