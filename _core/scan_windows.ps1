# nxt-vuln-sweep 호스트 수집기 (Windows). 공지와 무관하게 Java, MySQL, Oracle 계열 설치/실행 정보를 모은다.
# 출력 형식은 _core/COLLECTORS.md 참고. 탐지 대상을 늘릴 때는 FIND 이름 목록과 README를 함께 고친다.
# 읽기 전용: 레지스트리, 파일, 프로세스 조회와 버전 출력만 하고 아무것도 설치하거나 바꾸지 않는다.
# 출력: 탭 구분 한 줄이 발견 항목 하나. 결과를 바로바로 출력하므로 시간 초과로 끊겨도 앞부분은 남는다. 마지막 줄이 END 이면 끝까지 실행된 것이다.
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
try { (Get-Process -Id $PID).PriorityClass = 'Idle' } catch {}
$t0 = Get-Date

function O { (($args | ForEach-Object { "$_" -replace "[`t`r`n]", ' ' }) -join "`t") }
function RelVars($jh) {
  if (-not $jh) { return '' }
  foreach ($f in @((Join-Path $jh 'release'), (Join-Path (Split-Path $jh -Parent) 'release'))) {
    if (Test-Path -LiteralPath $f) {
      return ((Get-Content -LiteralPath $f | Where-Object { $_ -match '^(JAVA_VERSION|JAVA_RUNTIME_VERSION|IMPLEMENTOR|IMPLEMENTOR_VERSION|GRAALVM_VERSION)=' }) -replace '"', '') -join ' '
    }
  }
  return ''
}

# ---- META
$os = Get-CimInstance Win32_OperatingSystem
O 'META' 'collector' 'scan_windows.ps1 2026.11.1'
O 'META' 'host' $env:COMPUTERNAME
O 'META' 'os' "$($os.Caption) $($os.Version)"
O 'META' 'cpu' ((Get-CimInstance Win32_Processor | Select-Object -First 1).Name)

# ---- PKG: 설치된 프로그램 (64비트, 32비트 Uninstall 키)
$keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
Get-ItemProperty -Path $keys | Where-Object { $_.DisplayName -match 'Java|JDK|JRE|Corretto|Temurin|Zulu|GraalVM|MySQL|MariaDB|Oracle|VirtualBox' } |
  Sort-Object DisplayName, DisplayVersion -Unique | Select-Object -First 60 | ForEach-Object { O 'PKG' $_.DisplayName $_.DisplayVersion $_.Publisher }

# ---- PROC: jvm.dll을 올린 모든 프로세스 (java.exe, Tomcat 서비스(tomcatN.exe) 같은 내장 JVM 포함)와 MySQL/Oracle 프로세스
$n = 0
foreach ($pr in Get-Process) {
  if ($n -ge 40) { break }
  $m = $null
  try { $m = $pr.Modules | Where-Object { $_.ModuleName -eq 'jvm.dll' } | Select-Object -First 1 } catch {}
  $isDb = $pr.ProcessName -in @('mysqld', 'oracle', 'tnslsnr', 'mariadbd')
  if (-not $m -and -not $isDb) { continue }
  $n++
  $rv = ''
  if ($m) {
    $jh = Split-Path (Split-Path (Split-Path $m.FileName -Parent) -Parent) -Parent
    $rv = RelVars $jh
    if (-not $rv) { $rv = "jvm.dll=$($m.FileName) $($m.FileVersionInfo.FileVersion)" }
  }
  $cl = (Get-CimInstance Win32_Process -Filter "ProcessId=$($pr.Id)").CommandLine
  $hint = ''
  if ("$cl" -match '-jar\s+"?([^"\s]+)') { $hint = Split-Path $Matches[1] -Leaf }
  elseif ("$cl" -match '-D(catalina\.base|weblogic\.Name)=("[^"]+"|\S+)') { $hint = $Matches[0] }
  if ($hint -match 'pass|secret|token|key') { $hint = '' }
  O 'PROC' $pr.Id $pr.ProcessName $pr.ProcessName $pr.Path 'host' $rv $hint ''
}

# ---- SVC: Java, Tomcat, MySQL, Oracle 계열 서비스
Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'java|jdk|jre|tomcat|mysql|oracle|weblogic|jboss|wildfly|elastic|jenkins|prunsrv' } |
  Select-Object -First 40 | ForEach-Object {
    $exe = if ($_.PathName -match '^\s*"([^"]+)"') { $Matches[1] } elseif ($_.PathName -match '^\s*(\S+)') { $Matches[1] } else { '' }
    O 'SVC' $_.Name $_.State $exe
  }

# ---- PROCRUN: Tomcat 등 procrun 서비스가 쓰는 JVM 경로
foreach ($k in 'HKLM:\SOFTWARE\Apache Software Foundation\Procrun 2.0', 'HKLM:\SOFTWARE\WOW6432Node\Apache Software Foundation\Procrun 2.0') {
  Get-ChildItem -Path $k | ForEach-Object {
    $jvm = (Get-ItemProperty -Path (Join-Path $_.PSPath 'Parameters\Java')).Jvm
    if ($jvm) {
      $jh = Split-Path (Split-Path (Split-Path $jvm -Parent) -Parent) -Parent
      O 'PROCRUN' $_.PSChildName $jvm (RelVars $jh)
    }
  }
}

# ---- ORACLE: 레지스트리와 oraInventory에 등록된 Oracle Home, 적용 패치 목록
$homes = @()
foreach ($k in 'HKLM:\SOFTWARE\ORACLE', 'HKLM:\SOFTWARE\WOW6432Node\ORACLE') {
  Get-ChildItem -Path $k | ForEach-Object { $h = (Get-ItemProperty -Path $_.PSPath).ORACLE_HOME; if ($h) { $homes += $h } }
}
$invXml = 'C:\Program Files\Oracle\Inventory\ContentsXML\inventory.xml'
if (Test-Path -LiteralPath $invXml) {
  $homes += ([regex]::Matches((Get-Content -LiteralPath $invXml -Raw), 'LOC="([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
}
foreach ($h in ($homes | Sort-Object -Unique)) {
  if (-not (Test-Path -LiteralPath $h)) { continue }
  O 'OHOME' $h ''
  $reg = Join-Path $h 'inventory\registry.xml'
  if (Test-Path -LiteralPath $reg) {
    [regex]::Matches((Get-Content -LiteralPath $reg -Raw), '<distribution [^>]*>') | ForEach-Object {
      O 'OREG' $h (([regex]::Matches($_.Value, '(name|version|status)="[^"]*"') | ForEach-Object { $_.Value }) -join ' ')
    }
  }
  $op = Join-Path $h 'OPatch\opatch.bat'
  if (Test-Path -LiteralPath $op) {
    $env:ORACLE_HOME = $h
    $res = @(& cmd /c "`"$op`" lspatches" 2>&1 | ForEach-Object { "$_" })
    # 오래된 OPatch(11.x)는 lspatches를 지원하지 않으므로 lsinventory에서 제품/패치 줄만 추린다
    if (($res -join ' ') -match 'error code|syntax') {
      $res = @(& cmd /c "`"$op`" lsinventory" 2>&1 | ForEach-Object { "$_" } | Where-Object { $_ -match '^(Patch |Oracle [A-Za-z].*\d+\.\d|There are|Installed Top-level)' })
    }
    $res | Where-Object { $_ -and $_ -notmatch 'OPatch succeeded' } | Select-Object -First 15 | ForEach-Object { O 'OPATCH' $h $_ }
  }
}

# ---- FIND: 고정 디스크 전체 (C:\Windows 등 시스템 폴더 제외)
$names = @('java.exe', 'mysqld.exe', 'mysql.exe', 'mysqlsh.exe', 'weblogic.jar', 'ords.war', 'VBoxManage.exe')
$skip = @('Windows', '$Recycle.Bin', 'System Volume Information', 'Recovery', 'PerfLogs')
$cnt = 0
foreach ($d in (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3')) {
  foreach ($r in (Get-ChildItem -LiteralPath ($d.DeviceID + '\') -Directory -Force | Where-Object { $skip -notcontains $_.Name })) {
    foreach ($f in (Get-ChildItem -LiteralPath $r.FullName -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $names -contains $_.Name })) {
      $cnt++
      if ($cnt -gt 80) { continue }
      $p = $f.FullName
      if ($f.Name -eq 'java.exe') {
        $jh = Split-Path (Split-Path $p -Parent) -Parent
        O 'JAVA' 'host' $p (RelVars $jh) "$($f.VersionInfo.ProductName) $($f.VersionInfo.ProductVersion) file=$($f.VersionInfo.FileVersion)"
      } elseif ($f.Name -in @('mysqld.exe', 'mysql.exe', 'mysqlsh.exe')) {
        $v = (& $p --version 2>&1 | Select-Object -First 1)
        O 'MYSQL' 'host' $p "$v"
      } else {
        O 'FILE' 'host' $p
      }
    }
  }
}
if ($cnt -gt 80) { O 'TRUNC' 'FIND' $cnt }

O 'END' ("{0}s" -f [int]((Get-Date) - $t0).TotalSeconds)
