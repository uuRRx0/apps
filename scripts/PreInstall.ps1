$registryPath = "HKCU:SOFTWARE\Typora\"

# If registry path doesn't exist, create it.
If (-NOT (Test-Path $registryPath)) {
  New-Item $registryPath | Out-Null
}
# If registry has any access, remove it.
$Acl = Get-Acl $registryPath
If ($Acl.Access) {
  $Acl.SetAccessRuleProtection($true, $false)
  $Acl.Access | ForEach-Object { $Acl.RemoveAccessRule($_) }
  $Acl | Set-Acl -Path $registryPath
}