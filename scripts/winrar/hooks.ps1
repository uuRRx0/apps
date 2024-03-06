function NotifyShellChange {
  $signature = @'
[DllImport("shell32.dll")]
public static extern void SHChangeNotify(int wEventId, int uFlags, IntPtr dwItem1, IntPtr dwItem2);
'@

  $shell32 = Add-Type -MemberDefinition $signature -Name 'Shell32Lib' -Namespace Win32 -PassThru

  # 然后调用SHChangeNotify函数
  $SHCNE_ASSOCCHANGED = 0x08000000  # 文件关联更改事件
  $SHCNF_IDLIST = 0x0000  # dwItem1和dwItem2都是PIDL列表

  # 示例调用
  $shell32::SHChangeNotify($SHCNE_ASSOCCHANGED, $SHCNF_IDLIST, [IntPtr]::Zero, [IntPtr]::Zero)
}

function RegAccess {
  [CmdLetBinding()]
  Param(
    [Parameter(ValueFromPipeline = $true, Position = 0, Mandatory = $true)]
    [Alias("FullName")]
    [string]$path,
    $Encoding = "utf8",
    [Parameter(Mandatory = $false)]
    [Alias("Import")]
    [switch]$importReg = $false
  )

  Process {
    switch (test-path $path -pathtype container) {
      $true { $files = (get-childitem -path $path -recurse -force -file -filter "*.reg").fullname }
      $false { if ($path.endswith(".reg")) { $files = $path } }
    }
    foreach ($File in $Files) {
      [string]$text = $nul
      $FileContent = Get-Content $File | Where-Object { ![string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() }
      $joinedlines = @()
      for ($i = 0; $i -lt $FileContent.count; $i++) {
        if ($FileContent[$i].EndsWith("\")) {
          $text = $text + ($FileContent[$i] -replace "\\").trim()
        }
        else {
          $joinedlines += $text + $FileContent[$i]
          [string]$text = $nul
        }
      }

      $procetPath = @()
      foreach ($joinedline in $joinedlines) {
        if ($joinedline.StartsWith("[HKEY") -and $joinedline.EndsWith("]")) {
          $procetPath += $joinedline          
          ChangeAccess -Path $joinedline.Trim("[", "]") -DenyDelete $importReg | Out-Null
        }          
      }
    }
  }
}

function ChangeAccess {
  [CmdLetBinding()]
  Param(
    [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
    [Alias("Path")]
    [string]$regKeyPath,
    $Encoding = "utf8",
    [Parameter(Mandatory = $false)]
    [Alias("DenyDelete")]
    [switch]$setRule = $false
  )  

  Begin {
    $hive = @{
      "HKEY_CLASSES_ROOT"   = "ClassesRoot"
      "HKEY_CURRENT_USER"   = "CurrentUser"
      "HKEY_LOCAL_MACHINE"  = "LocalMachine"
      "HKEY_USERS"          = "Users"
      "HKEY_CURRENT_CONFIG" = "CurrentConfig"
    }    
  
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule('Everyone', "Delete", "None", "None", "Deny")
  }
  Process {
    $hivename = $regKeyPath.split('\')[0]
    $subKey = $regKeyPath -replace 'HKEY_[^\\]+\\'
    $root = $hive.$hivename
    $key = [Microsoft.Win32.Registry]::$root.OpenSubKey(
      $subKey,
      'ReadWriteSubTree', 'ChangePermissions')
  
    if ($key) {
      $acl = $key.GetAccessControl()
      # Write-Output $key.GetAccessControl() | Format-List
      $acl.Access | ForEach-Object {
        if ($_.IdentityReference -eq "Everyone") {
          $Acl.RemoveAccessRule($_) | Out-Null
        }
      }
      if ($setRule) {
        $acl.SetAccessRule($rule)
      }
    
      $key.SetAccessControl($acl)
    
      # Write-Output $key.GetAccessControl() | Format-List
  
    }
  }
}

function pre_install {
  if (!(is_admin)) { Get-error "$app requires admin rights to $cmd"; break }
  'rarreg.key' | ForEach-Object {
    if (!(Test-Path "$persist_dir\$_") -and (Test-Path "$bucketsdir\$bucket\scripts\WinRAR\$_")) {
      Copy-Item "$bucketsdir\$bucket\scripts\WinRAR\$_" -Destination "$dir" | Out-Null
    }
  }
  # if (!(Test-Path "$persist_dir\WinRar.ini")) { New-Item "$dir\WinRar.ini" | Out-Null }

  # 获取匹配文件并删除（忽略错误）
  Get-ChildItem -Path $dir -Filter "*.tmp" -File | ForEach-Object {
    Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
  }
}

function post_install {
  $appScripts = "$bucketsdir\$bucket\scripts\$app"
  "RarExt.dll", "RarExt32.dll" | ForEach-Object {
    if ((Test-Path "$dir\$_")) {
      Rename-Item -Path "$dir\$_" -NewName "$_.$(Get-Date -F yyyyMMddTHHmmssffff).0.tmp" -Force
    }
    if ((Test-Path "$appScripts\$_")) {
      Copy-Item -Path "$appScripts\$_" -Destination "$dir\$_"
    }
  }
  "Setting.reg", "602ContextMenu.reg" | ForEach-Object {
    $path = "$appScripts\$_"
    if ((Test-Path $path)) {
      cmd /c regedit.exe /s $path
    }
  }
  # import and deny delete registy path
  RegAccess "$appScripts\602ContextMenu.reg" -Import
  NotifyShellChange

  # 删除临时文件（忽略错误）
  Get-ChildItem -Path $dir -Filter "*.tmp" -File | ForEach-Object {
    Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
  }
  # # 删除 WinRar.ini
  # Get-ChildItem -Path $dir -Filter "WinRar.ini" -File | ForEach-Object {
  #   Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
  # }
}

function pre_uninstall {
  if (!(is_admin)) { Get-error "$app requires admin rights to $cmd"; break }
  $appScripts = "$bucketsdir\$($install.bucket)\scripts\$app"
  # remove deny delete access
  RegAccess "$appScripts\602ContextMenu.reg"
}

function post_uninstall {
  # 删除临时文件
  Get-ChildItem -Path $dir -Filter "*.tmp" -File | ForEach-Object {
    Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
  }
}

Switch ($HookType) {
  'pre_install' {
    pre_install
  }
  'post_install' {
    post_install
  }
  'pre_uninstall' {
    pre_uninstall
  }
  'post_uninstall' {
    post_uninstall
  }
  default {
    exit 0
  }
}