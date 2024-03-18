function NotifyShellChange {
  $code = @'
  [System.Runtime.InteropServices.DllImport("Shell32.dll")] 
  private static extern int SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);

  public static void Refresh()  {
      SHChangeNotify(0x8000000, 0x1000, IntPtr.Zero, IntPtr.Zero);    
  }
'@

  Add-Type -MemberDefinition $code -Namespace WinAPI -Name Explorer 
  [WinAPI.Explorer]::Refresh()
}

function RegAccess {
  [CmdLetBinding()]
  Param(
    [Parameter(ValueFromPipeline = $true, Position = 0, Mandatory = $true)]
    [Alias("FullName")]
    [string]$path,
    $Encoding = "utf8",
    [Parameter(Mandatory = $false)]
    [Alias("RefuseDelete")]
    [switch]$denyDelete = $false
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
          ChangeAccess -Path $joinedline.Trim("[", "]") -DenyDelete:$denyDelete | Out-Null
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
      $acl.Access | ForEach-Object {
        if ($_.IdentityReference -eq "Everyone" -and $_.IsInherited -eq $false -and $_.AccessControlType -eq "Deny") {
          $Acl.RemoveAccessRule($_) | Out-Null
        }
      }
      if ($setRule) {
        $acl.SetAccessRule($rule)
      }    
      $key.SetAccessControl($acl)
      $key.Close()
    }
  }
}

# 删除临时文件
function RemoveTmp {
  param($dir)
  if (Test-Path "$dir/..") {
    Get-ChildItem -Path "$dir/.." -Recurse -Filter "*.tmp" -File | ForEach-Object {
      Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
    }
  }
}

function RestoreWin10RightClickMenu {
  $appScripts = "$bucketsdir\$bucket\scripts\$app"
  # 如果是win10旧版菜单
  if (Test-Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32") {
    "RarExt.dll", "RarExt32.dll" | ForEach-Object {
      # 如果dll文件版本不为6.2.0,，则复制旧版dll文件到当前目录
      if ((Get-Item "$dir\$_").VersionInfo.ProductVersion -ne '6.2.0' -and (Test-Path "$appScripts\$_")) {
        Rename-Item -Path "$dir\$_" -NewName "$_.$(Get-Date -F yyyyMMddTHHmmssffff).0.tmp" -Force
        Copy-Item -Path "$appScripts\$_" -Destination "$dir\$_"
      }
    }
    # 添加默认建议设置，及还原旧版右键注册项
    "Setting.reg", "602ContextMenu.reg" | ForEach-Object {
      $path = "$appScripts\$_"
      if ((Test-Path $path)) {
        cmd /c regedit.exe /s $path
      }
    }
    # 设置权限，保护相关注册项，防止WinRAR删除
    RegAccess "$appScripts\602ContextMenu.reg" -RefuseDelete
    # 通知shell关联更新
    NotifyShellChange
  }
  else {
    # 默认建议设置
    "Setting.reg" | ForEach-Object {
      $path = "$appScripts\$_"
      if ((Test-Path $path)) {
        cmd /c regedit.exe /s $path
      }
    }
  }
}

function pre_install {
  if (!(is_admin)) { error "$app requires admin rights to $cmd"; exit 1 }
  if (!(Test-Path "$persist_dir\rarreg.key")) { New-Item "$dir\rarreg.key" | Out-Null }
  # if (!(Test-Path "$persist_dir\WinRar.ini")) { New-Item "$dir\WinRar.ini" | Out-Null }
  'rarreg.key' | ForEach-Object {
    if (!(Test-Path "$persist_dir\$_") -and (Test-Path "$bucketsdir\$bucket\scripts\WinRAR\$_")) {
      Copy-Item "$bucketsdir\$bucket\scripts\WinRAR\$_" -Destination "$dir" | Out-Null
    }
  }
  RemoveTmp $dir
}

function post_install {
  RestoreWin10RightClickMenu
  RemoveTmp $dir
}

function pre_uninstall {
  if (!(is_admin)) { Get-error "$app requires admin rights to $cmd"; exit 1 }
  $appScripts = "$bucketsdir\$($install.bucket)\scripts\$app"
  # remove deny delete access
  RegAccess "$appScripts\602ContextMenu.reg"
}

function post_uninstall {
  RemoveTmp $dir
  NotifyShellChange
}

function uninstall {
  $filePath = "$dir\Uninstall.exe"
  cmd /c "$filePath /s"
  $maxWaitTimeInSeconds = 30

  $startTime = (Get-Date)
  do {
    if (-not (Test-Path -Path $filePath)) {
      break
    }
    Start-Sleep -Seconds 1
  } until (((Get-Date) - $startTime).TotalSeconds -gt $maxWaitTimeInSeconds)
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