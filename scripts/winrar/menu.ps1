Param($mode)

# WinRAR旧版右键菜单程序
# 描述：Win11，WinRAR从6.10开始适配了新的右键菜单，导致在Win11系统中还原为Win10右键菜单的用户不能直接使用非层叠的右键菜单选项，只能在设置层叠菜单选项后，每次操作需要点击两次，尤为不便。此程序则是为此而生，可以直接一步到位。
#  程序设计
#   前置：判断是否为管理员、Win11
#   提供功能：
#    1.安装（且自动设置右键菜单）
#    2.卸载（且移除相关"自动设置右键菜单"的注册表选项）
#    3.自动设置右键菜单（依据右键菜单的样式，Win10|Win11）
#    4.还原（移除所有该程序带来的改变）
#    5.右键菜单关联选项设置（Win11上未设置层叠选项时是看不见的）
#    6.设置推荐选项

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { '.' }
$contextMenuReg = 'Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\WinRAR]
@="{B41DB860-64E4-11D2-9906-E49FADC173CA}"
[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\WinRAR32]
@="{B41DB860-8EE4-11D2-9906-E49FADC173CA}"
[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Folder\ShellEx\ContextMenuHandlers\WinRAR]
@="{B41DB860-64E4-11D2-9906-E49FADC173CA}"
[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Folder\ShellEx\ContextMenuHandlers\WinRAR32]
@="{B41DB860-8EE4-11D2-9906-E49FADC173CA}"
[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\lnkfile\shellex\ContextMenuHandlers\WinRAR]
@="{B41DB860-64E4-11D2-9906-E49FADC173CA}"
[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\lnkfile\shellex\ContextMenuHandlers\WinRAR32]
@="{B41DB860-8EE4-11D2-9906-E49FADC173CA}"
[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WinRAR\shellex\ContextMenuHandlers]
[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WinRAR\shellex\ContextMenuHandlers\{B41DB860-64E4-11D2-9906-E49FADC173CA}]
@=""
[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WinRAR\shellex\ContextMenuHandlers\{B41DB860-8EE4-11D2-9906-E49FADC173CA}]
@=""
[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WinRAR.ZIP\shellex\ContextMenuHandlers]
[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WinRAR.ZIP\shellex\ContextMenuHandlers\{B41DB860-64E4-11D2-9906-E49FADC173CA}]
@=""
[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WinRAR.ZIP\shellex\ContextMenuHandlers\{B41DB860-8EE4-11D2-9906-E49FADC173CA}]
@=""'

$suggestReg = 'Windows Registry Editor Version 5.00

; 设置右键菜单关联项目
[HKEY_CURRENT_USER\Software\WinRAR\Setup\MenuItems]
"ExtrTo"=dword:00000000
"ExtrHere"=dword:00000000
"Extr"=dword:00000001
"ExtrSep"=dword:00000001
"OpenSFX"=dword:00000001
"OpenArc"=dword:00000000
"AddTo"=dword:00000001
"AddArc"=dword:00000001
"EmailArc"=dword:00000000
"EmailOpt"=dword:00000000
"Test"=dword:00000000
"Convert"=dword:00000000

; 从解压路径去除多余的文件夹(R)
[HKEY_CURRENT_USER\Software\WinRAR\Extraction]
"RemoveRedundantFolder"=dword:00000001

; 在资源管理器显示文件(X) 完成操作后(W) 关闭 WinRAR
[HKEY_CURRENT_USER\Software\WinRAR\Extraction\Profile]
"ShowExplorer"=dword:00000001
"Shutdown"=dword:00000005'

function Menu {
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory)]
    [ValidatePattern("[1-46]")]
    [string]$actionNum
  )
  Begin {
    $isAdmin = JudgeAdmin
  }
  Process {
    if (-not $isAdmin) {
      # 自动提升权限重新运行该脚本
      $boundPara = ($MyInvocation.BoundParameters.Keys | ForEach-Object { '-{0} {1}' -f $_ , $MyInvocation.BoundParameters[$_] } ) -join ' '
      $currentFile = $MyInvocation.MyCommand.Definition
      $fullPara = $boundPara + ' ' + $args -join ' '
      Start-Process "$psHome\powershell.exe" -ArgumentList "$currentFile $fullPara" -verb runas
      return
    }
    Switch ($actionNum) {
      1 {
        InstallApp -Silent
        UpdateMenu
      }
      2 {
        ResetMenu
        UninstallApp -Silent
      }
      3 {
        UpdateMenu
      }
      4 {
        ResetMenu
      }
      6 {
        $suggestReg | AddToRegedit
      }
    }
  }
}

function GetAppPath {
  $installedPath = try { (Get-ItemProperty "HKLM:SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\WinRAR.exe" -ErrorAction SilentlyContinue).Path } catch { $scriptDir }
  "$installedPath/Uninstall.exe"
}

function InstallApp {
  [CmdletBinding()]
  Param(
    [switch]$Silent
  )
  $file = GetAppPath
  if ((Test-Path $file) -and (Get-Item $file).VersionInfo.FileDescription -eq "卸载 WinRAR") {
    cmd /c "$file /setup$(if($Silent){ " /s" } else { '' })"
  }
}

function UninstallApp {
  [CmdletBinding()]
  Param(
    [switch]$Silent
  )
  $file = GetAppPath
  if ((Test-Path $file) -and (Get-Item $file).VersionInfo.FileDescription -eq "卸载 WinRAR") {
    cmd /c "$file$(if($Silent){ " /s" } else { '' })"
  }
}

function JudgeAdmin {
  $admin = [security.principal.windowsbuiltinrole]::administrator
  $id = [security.principal.windowsidentity]::getcurrent()
  ([security.principal.windowsprincipal]($id)).isinrole($admin)
}

function JudgeWin11 {
  $isPS7 = $psversiontable.PSVersion -match '7.\d.\d'
  $sysInfo = if ($isPS7) {
    (Get-CimInstance -ClassName Win32_OperatingSystem)
  }
  else {
    (Get-WmiObject Win32_OperatingSystem)
  }
  $sysInfo.Caption -Match "Windows 11"
}

function JudgeWin10Menu {
  Test-Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
}

function Out-UTF8File {
  param(
    [Parameter(Mandatory = $True, Position = 0)]
    [Alias("Path")]
    [String] $FilePath,
    [Switch] $Append,
    [Switch] $NoNewLine,
    [Parameter(ValueFromPipeline = $True)]
    [PSObject] $InputObject
  )
  process {
    if ($Append) {
      [System.IO.File]::AppendAllText($FilePath, $InputObject)
    }
    else {
      if (!$NoNewLine) {
        # Ref: https://stackoverflow.com/questions/5596982
        # Performance Note: `WriteAllLines` throttles memory usage while
        # `WriteAllText` needs to keep the complete string in memory.
        [System.IO.File]::WriteAllLines($FilePath, $InputObject)
      }
      else {
        # However `WriteAllText` does not add ending newline.
        [System.IO.File]::WriteAllText($FilePath, $InputObject)
      }
    }
  }
}

function RegAccess {
  [CmdLetBinding()]
  Param(
    [Parameter(ParameterSetName = "Value", ValueFromPipeline = $true, Position = 0, Mandatory = $true)]
    [AllowEmptyString()]
    [string]$Value
  )
  Process {
    if ($Value -match "\[(?<delete>-?)(HKEY[^\]]+)\]") {
      ChangeAccess -Path $Matches[1] -Delete:$([boolean]$Matches.delete) | Out-Null
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
    [Alias("Delete")]
    [switch]$remove = $false
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
      # 如果不删除，则添加拒绝删除的规则
      if (!$remove) {
        $acl.SetAccessRule($rule)
      }    
      $key.SetAccessControl($acl)
      $key.Close()
      if ($remove) {
        [Microsoft.Win32.Registry]::$root.DeleteSubKeyTree($subKey)
      }
    }
  }
}
function GetShowVersion {
  [CmdletBinding()]
  Param(
    [string]$ProductVersion
  )
  $majorVersion = $ProductVersion.Split('.') | Select-Object -First 1;
  $minorVersion = ($ProductVersion.Split('.') | Select-Object -Skip 1 -First 1).padLeft(2, '0');
  "v$majorVersion$minorVersion"
}
function GetFileInfo {
  [CmdletBinding()]
  Param(
    [string]$Path
  )
  $item = Get-Item $Path
  $vInfo = $item.VersionInfo
  $version = $vInfo.ProductVersion
  $fileInfo = @{
    'version'     = $version
    'showVersion' = GetShowVersion $version
    'name'        = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    'ext'         = [System.IO.Path]::GetExtension($Path)
  }
  $fileInfo
}

function MoveFile {
  [CmdletBinding(DefaultParameterSetName = "NewName")]
  Param(
    [Parameter(Position = 0, ValueFromPipeline = $true, Mandatory = $true)]
    [string]$Path,
    [string]$Destination,
    [Parameter(ParameterSetName = "NewName", Mandatory)]
    [string]$NewName,
    [Alias('Origin', 'o')]
    [Parameter(ParameterSetName = "OriginName", Mandatory)]
    [switch]$OriginName,
    [Parameter(ParameterSetName = "FormatName", Mandatory)]
    [Alias('Format', 'f')]
    [switch]$FormatName,
    [Alias('UnFormat', 'uf')]
    [Parameter(ParameterSetName = "UnFormatName", Mandatory)]
    [switch]$UnFormatName,
    [switch]$Copy,
    [switch]$Backup,
    [switch]$ExistBackupFormat
  )
  Begin {
    if (!(Test-Path $Path)) {
      exit 0
    }
    $parent = if ($Destination) { $Destination } else { (Split-Path $Path -Parent) }
    $NewPath = Switch ($true) {
      $OriginName {
        $name = (Get-Item $Path).VersionInfo.OriginalFilename
        "$parent\$name"
        continue
      }
      $FormatName {
        $info = GetFileInfo $Path
        $showVersion = $info.showVersion
        $name = $info.name
        $ext = $info.ext
        $fileName = if ($showVersion) { "$name`_$showVersion$ext" } else { $name }
        "$parent\$fileName"
        continue
      }
      $UnFormatName {
        $info = GetFileInfo $Path
        $showVersion = $info.showVersion
        $name = $info.name
        $ext = $info.ext
        $fileName = $name -replace "_$showVersion"
        "$parent\$fileName$ext"
        continue
      }
      ($null -ne $NewName -and $NewName) {
        if ([System.IO.Path]::GetPathRoot($NewName)) { $NewName } else { "$parent\$NewName" }
        continue
      }
    }
  }
  Process {
    if ($Backup -and (Test-Path $NewPath)) {
      MoveFile $NewPath -NewName "$NewPath.bak"
    }
    if ($ExistBackupFormat -and (Test-Path $NewPath)) {
      MoveFile $NewPath -FormatName
    }
    if ($Copy) {
      Copy-Item -Path $Path -Destination $NewPath -Force -ErrorAction SilentlyContinue
    }
    else {
      Move-Item -Path $Path -Destination $NewPath -Force -ErrorAction SilentlyContinue
    }
    $NewPath
  }
}

function Update-ExplorerIcon {
<#
.SYNOPSIS
    Updates Explorer icons
.DESCRIPTION
    Updates Explorer icons
.NOTES
    Source: https://community.idera.com/database-tools/powershell/powertips/b/tips/posts/refreshing-icon-cache
#>

    [CmdletBinding(ConfirmImpact='Low')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions','')]
    param()

    $code = @'
private static readonly IntPtr HWND_BROADCAST = new IntPtr(0xffff);
private const int WM_SETTINGCHANGE = 0x1a;
private const int SMTO_ABORTIFHUNG = 0x0002;
 
[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
 static extern bool SendNotifyMessage(IntPtr hWnd, uint Msg, UIntPtr wParam,
   IntPtr lParam);
 
[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
  private static extern IntPtr SendMessageTimeout ( IntPtr hWnd, int Msg, IntPtr wParam, string lParam, uint fuFlags, uint uTimeout, IntPtr lpdwResult );
 
[System.Runtime.InteropServices.DllImport("Shell32.dll")]
private static extern int SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);
 
public static void Refresh() {
    SHChangeNotify(0x8000000, 0x1000, IntPtr.Zero, IntPtr.Zero);
    SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, IntPtr.Zero, null, SMTO_ABORTIFHUNG, 100, IntPtr.Zero);
}
'@

    Add-Type -MemberDefinition $code -Namespace MyWinAPI -Name Explorer
    [MyWinAPI.Explorer]::Refresh()

}

Function Refresh{
  $source = @"
using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
namespace FileEncryptProject.Algorithm
{
 public class DesktopRefurbish
 {
   [DllImport("shell32.dll")]
   public static extern void SHChangeNotify(HChangeNotifyEventID wEventId, HChangeNotifyFlags uFlags, IntPtr dwItem1, IntPtr dwItem2);
   public static void DeskRef()
   {
     SHChangeNotify(HChangeNotifyEventID.SHCNE_ASSOCCHANGED, HChangeNotifyFlags.SHCNF_IDLIST, IntPtr.Zero, IntPtr.Zero);
   }
 }
 #region public enum HChangeNotifyFlags
 [Flags]
 public enum HChangeNotifyFlags
 {
   SHCNF_DWORD = 0x0003,
   SHCNF_IDLIST = 0x0000,
   SHCNF_PATHA = 0x0001,
   SHCNF_PATHW = 0x0005,
   SHCNF_PRINTERA = 0x0002,
   SHCNF_PRINTERW = 0x0006,
   SHCNF_FLUSH = 0x1000,
   SHCNF_FLUSHNOWAIT = 0x2000
 }
 #endregion//enum HChangeNotifyFlags
 #region enum HChangeNotifyEventID
 [Flags]
 public enum HChangeNotifyEventID
 {
   SHCNE_ALLEVENTS = 0x7FFFFFFF,
   SHCNE_ASSOCCHANGED = 0x08000000,
   SHCNE_ATTRIBUTES = 0x00000800,
   SHCNE_CREATE = 0x00000002,
   SHCNE_DELETE = 0x00000004,
   SHCNE_DRIVEADD = 0x00000100,
   SHCNE_DRIVEADDGUI = 0x00010000,
   SHCNE_DRIVEREMOVED = 0x00000080,
   SHCNE_EXTENDED_EVENT = 0x04000000,
   SHCNE_FREESPACE = 0x00040000,
   SHCNE_MEDIAINSERTED = 0x00000020,
   SHCNE_MEDIAREMOVED = 0x00000040,
   SHCNE_MKDIR = 0x00000008,
   SHCNE_NETSHARE = 0x00000200,
   SHCNE_NETUNSHARE = 0x00000400,
   SHCNE_RENAMEFOLDER = 0x00020000,
   SHCNE_RENAMEITEM = 0x00000001,
   SHCNE_RMDIR = 0x00000010,
   SHCNE_SERVERDISCONNECT = 0x00004000,
   SHCNE_UPDATEDIR = 0x00001000,
   SHCNE_UPDATEIMAGE = 0x00008000,
 }
 #endregion
}
"@
    Add-Type -TypeDefinition $source
   [FileEncryptProject.Algorithm.DesktopRefurbish]::DeskRef()
}

function ReplaceDll {
  [CmdletBinding()]
  Param(
    [Parameter(ValueFromPipeline = $true)]
    [string]$version
  )
  if ($version -match "\d+\.\d+\.\d") {
    $version = GetShowVersion $version
  }
  # $url = "https://www.win-rar.com/fileadmin/winrar-versions/sc/sc20210616/wrr/wrar602sc.exe"
  # $url64 = "https://www.win-rar.com/fileadmin/winrar-versions/sc/sc20210616/wrr/winrar-x64-602sc.exe"
  $installedPath = try { (Get-ItemProperty "HKLM:SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\WinRAR.exe" -ErrorAction SilentlyContinue).Path } catch { $scriptDir }
  'RarExt', 'RarExt32' | ForEach-Object {
    $NewName = "$_.dll"
    $path = "$installedPath\$NewName"
    $replaceFiles = @("$scriptDir\$_`_$version.dll", "$installedPath\$_`_$version.dll")
    Switch ($replaceFiles) {
      { (Test-Path $path) -and ((GetFileInfo $path).showVersion -eq $version) } { continue }
      { !(Test-Path $_) } { continue }
      default {
        MoveFile $_ -Destination $installedPath -NewName $NewName -ExistBackupFormat -Copy
        Refresh
      }
    }
  }
}

function RestoreDll {
  [CmdletBinding()]
  Param()
  $file = GetAppPath
  if ((Test-Path $file) -and (Get-Item $file).VersionInfo.FileDescription -eq "卸载 WinRAR") {
    (Get-Item $file).VersionInfo.ProductVersion | ReplaceDll
  }
}

function AddToRegedit {
  [CmdletBinding()]
  Param(
    [Parameter(ValueFromPipeline = $true)]
    [string]$Value
  )
  $filePath = "$env:tmp\WinRAR.reg"
  # 生成reg文件
  $contextMenuReg | Out-UTF8File -FilePath $filePath
  # 导入reg文件
  cmd /c regedit.exe /s $filePath
  Remove-Item $filePath -Force -ErrorAction SilentlyContinue
}

function AddRegistry {
  $contextMenuReg | AddToRegedit
  # 保护reg
  $contextMenuReg -split "`r`n" | RegAccess
}

function RemoveRegistry {
  $array = $contextMenuReg -replace "\[H", "[-H" -split "`r`n"
  [Array]::Reverse($array)
  $array | RegAccess
}

function ToggleCascadedMenu {
  Param($Value)
  if ($null -eq $Value) {
    $Value = (Get-ItemProperty -Path "HKCU:\Software\WinRAR\Setup" -ErrorAction SilentlyContinue).CascadedMenu
    $Value = if ($Value -eq 0) { 1 } else { 0 }
  }
  New-Item -Path "HKCU:\Software\WinRAR\Setup" -ErrorAction SilentlyContinue | Out-Null
  Set-ItemProperty -Path "HKCU:\Software\WinRAR\Setup" -Name "CascadedMenu" -Value $Value
}

function SetWin10Menu {
  # 添加右键注册表，保护不被删除
  AddRegistry
  # 更改为展开菜单
  ToggleCascadedMenu 0
  # 更换dll文件
  ReplaceDll "v602"
}

function SetWin11Menu {
  # 更改注册表权限，删除右键注册表
  RemoveRegistry
  # 更改为折叠菜单
  ToggleCascadedMenu 1
  # 还原dll文件
  RestoreDll
}

function UpdateMenu {
  [CmdLetBinding()]
  Param(
    [switch]$Win10,
    [switch]$Win11
  )
  Process {
    if (-not $(JudgeWin11)) {
      # Win10系统本身就是旧版菜单模式，无需该程序
      exit 0
    }
    Switch ($true) {
      $Win10 {
        SetWin10Menu
      }
      $Win11 {
        SetWin11Menu
      }
      default {
        $isWin10Menu = JudgeWin10Menu
        if ($isWin10Menu) {
          SetWin10Menu
        }
        else {
          SetWin11Menu
        }
      }
    }
  }
}

function ResetMenu {
  if ($(JudgeWin11)) {
    UpdateMenu -Win11
  }
}

function Invoke {
  if ($mode -match "[1-46]") {
    Menu $mode
  }
  else {
    
    Write-Output "请选择以下选项进行操作："
    $str = '#    1.安装（且自动设置右键菜单）
    #    2.卸载（且移除相关"自动设置右键菜单"的注册表选项）
    #    3.自动设置右键菜单（依据右键菜单的样式，Win10|Win11）
    #    4.还原（移除所有该程序带来的改变）
    #    5.右键菜单关联选项设置（Win11上未设置层叠选项时是看不见的）
    #    6.设置推荐选项'
    $str | Select-String -Pattern "\d\.[^\r\n（]+" -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object {
      Write-Output $_.Value
    }
    $mode = Read-Host "请输入1-5:"
    Write-Output ''
    Invoke $mode
  }
}

if($null -ne $mode){
  Invoke $mode
}