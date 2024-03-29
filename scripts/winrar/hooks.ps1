function pre_install {
  if (!(is_admin)) { error "$app requires admin rights to $cmd"; exit 1 }
  if (!(Test-Path "$persist_dir\rarreg.key")) { New-Item "$dir\rarreg.key" | Out-Null }
  # if (!(Test-Path "$persist_dir\WinRar.ini")) { New-Item "$dir\WinRar.ini" | Out-Null }
  'rarreg.key' | ForEach-Object {
    if (!(Test-Path "$persist_dir\$_") -and (Test-Path "$bucketsdir\$bucket\scripts\WinRAR\$_")) {
      Copy-Item "$bucketsdir\$bucket\scripts\WinRAR\$_" -Destination "$dir" | Out-Null
    }
  }
}

function post_install {
  . "$PSScriptRoot\menu.ps1" 3
  if ($cmd -eq 'install'){
    . "$PSScriptRoot\menu.ps1" 6
  }
}

function pre_uninstall {
  if (!(is_admin)) { Get-error "$app requires admin rights to $cmd"; exit 1 }
}

function uninstall {
  $filePath = "$dir\Uninstall.exe"
  . "$PSScriptRoot\menu.ps1" 2
  $maxWaitTimeInSeconds = 30

  $startTime = (Get-Date)
  do {
    if (-not (Test-Path -Path $filePath)) {
      break
    }
    Start-Sleep -Seconds 1
  } until (((Get-Date) - $startTime).TotalSeconds -gt $maxWaitTimeInSeconds)
  # rename
  Get-ChildItem $dir -Filter "*.original" | ForEach-Object {
    Rename-Item -Path $_.FullName -NewName ($_.FullName -replace '.original') -ErrorAction SilentlyContinue
  }
}

Switch ($HookType) {
  'pre_install' {
    pre_install
    continue
  }
  'post_install' {
    post_install
    continue
  }
  'pre_uninstall' {
    pre_uninstall
    continue
  }
  default {
    exit 0
  }
}