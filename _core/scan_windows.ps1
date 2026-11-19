# nxt-vuln-sweep 호스트 수집기 (Windows). 공지와 무관하게 Java, MySQL, Oracle 계열, nginx 계열, PostgreSQL, Apache httpd, Node.js mongodb 패키지의 설치/실행 정보를 모은다.
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
# nginx.exe 내장 문자열에서 버전과 configure 인자의 모듈을 읽는다 (실행하지 않음)
function NgxInfo($p) {
  $txt = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($p))
  $b = ([regex]::Matches($txt, '(nginx|openresty|Tengine|Angie|freenginx)/\d+(\.\d+){1,3}|nginx-plus-r\d+(-p\d+)?') | ForEach-Object { $_.Value } | Sort-Object -Unique | Select-Object -First 5) -join ' '
  $m = ([regex]::Matches($txt, '--with-(http_v2_module|http_v3_module|http_ssl_module|mail|mail_ssl_module|stream|stream_ssl_module|stream_ssl_preread_module)(=dynamic)?(?=[\s"\x00]|$)') | ForEach-Object { $_.Value } | Sort-Object -Unique) -join ' '
  return @($b, $m)
}

# ---- META
$os = Get-CimInstance Win32_OperatingSystem
O 'META' 'collector' 'scan_windows.ps1 2026.11.3'
O 'META' 'host' $env:COMPUTERNAME
O 'META' 'os' "$($os.Caption) $($os.Version)"
O 'META' 'cpu' ((Get-CimInstance Win32_Processor | Select-Object -First 1).Name)

# ---- PKG: 설치된 프로그램 (64비트, 32비트 Uninstall 키)
$keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
Get-ItemProperty -Path $keys | Where-Object { $_.DisplayName -match 'Java|JDK|JRE|Corretto|Temurin|Zulu|GraalVM|MySQL|MariaDB|Oracle|VirtualBox|nginx|OpenResty|PostgreSQL|Apache|Node\.js' } |
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

# ---- NGINX: 실행 중인 nginx.exe (경로별 한 줄, master와 worker가 같은 경로). 설정 파일은 읽지 않는다
Get-Process -Name nginx, openresty | Where-Object { $_.Path } | Group-Object Path | Select-Object -First 10 | ForEach-Object {
  $pids = ($_.Group | Sort-Object Id | ForEach-Object { $_.Id }) -join ','
  $ni = NgxInfo $_.Name
  O 'NGINX' 'host' $_.Name $ni[0] $ni[1] "pid $pids" '' ''
}

# ---- SW 실행 중: postgres.exe, httpd.exe (경로별 한 줄). 설정 파일은 읽지 않는다
Get-Process -Name postgres, httpd | Where-Object { $_.Path } | Group-Object Path | Select-Object -First 10 | ForEach-Object {
  $key = if ($_.Name -match '(?i)postgres\.exe$') { 'postgresql' } else { 'httpd' }
  $pids = ($_.Group | Sort-Object Id | ForEach-Object { $_.Id }) -join ','
  O 'SW' $key 'host' $_.Name ((Get-Item -LiteralPath $_.Name).VersionInfo.ProductVersion) "pid $pids" '' '' ''
}
# Node.js 프로세스의 작업 폴더를 알 수 없으므로 명령행의 스크립트 경로에서 위로 올라가며 node_modules\mongodb 를 찾는다
Get-CimInstance Win32_Process -Filter "Name='node.exe'" | Select-Object -First 20 | ForEach-Object {
  $proc = $_
  if ("$($proc.CommandLine)" -match '(?i)node(\.exe)?"?\s+(?:--?\S+\s+)*"?([A-Za-z]:\\[^"]+?\.(?:c|m)?js)') {
    $dir = Split-Path $Matches[2] -Parent
    for ($i = 0; $i -lt 6 -and $dir; $i++) {
      $pj = Join-Path $dir 'node_modules\mongodb\package.json'
      if (Test-Path -LiteralPath $pj) {
        $v = ((Get-Content -LiteralPath $pj -Raw) | ConvertFrom-Json).version
        O 'SW' 'npm-mongodb' 'host' $pj $v "pid $($proc.ProcessId)" '' '' ''
        break
      }
      $dir = Split-Path $dir -Parent
    }
  }
}

# ---- SVC: Java, Tomcat, MySQL, Oracle 계열 서비스
Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'java|jdk|jre|tomcat|mysql|oracle|weblogic|jboss|wildfly|elastic|jenkins|prunsrv|nginx|postgres|httpd|apache' } |
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
$names = @('java.exe', 'mysqld.exe', 'mysql.exe', 'mysqlsh.exe', 'weblogic.jar', 'ords.war', 'VBoxManage.exe', 'nginx.exe', 'postgres.exe', 'pg_dump.exe', 'psql.exe', 'httpd.exe')
$skip = @('Windows', '$Recycle.Bin', 'System Volume Information', 'Recovery', 'PerfLogs')
$cnt = 0
foreach ($d in (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3')) {
  foreach ($r in (Get-ChildItem -LiteralPath ($d.DeviceID + '\') -Directory -Force | Where-Object { $skip -notcontains $_.Name })) {
    foreach ($f in (Get-ChildItem -LiteralPath $r.FullName -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $names -contains $_.Name -or $_.FullName -like '*\node_modules\mongodb\package.json' })) {
      $cnt++
      if ($cnt -gt 80) { continue }
      $p = $f.FullName
      if ($f.Name -eq 'java.exe') {
        $jh = Split-Path (Split-Path $p -Parent) -Parent
        O 'JAVA' 'host' $p (RelVars $jh) "$($f.VersionInfo.ProductName) $($f.VersionInfo.ProductVersion) file=$($f.VersionInfo.FileVersion)"
      } elseif ($f.Name -in @('mysqld.exe', 'mysql.exe', 'mysqlsh.exe')) {
        $v = (& $p --version 2>&1 | Select-Object -First 1)
        O 'MYSQL' 'host' $p "$v"
      } elseif ($f.Name -eq 'nginx.exe') {
        $ni = NgxInfo $p
        if ($ni[0]) { O 'NGINX' 'host' $p $ni[0] $ni[1] '' '' '' }
      } elseif ($f.Name -in @('postgres.exe', 'pg_dump.exe', 'psql.exe', 'httpd.exe')) {
        $key = @{ 'postgres.exe' = 'postgresql'; 'pg_dump.exe' = 'postgresql-client'; 'psql.exe' = 'postgresql-client'; 'httpd.exe' = 'httpd' }[$f.Name]
        if ($f.VersionInfo.ProductVersion) { O 'SW' $key 'host' $p $f.VersionInfo.ProductVersion '' '' '' '' }
      } elseif ($f.Name -eq 'package.json') {
        $j = (Get-Content -LiteralPath $p -Raw) | ConvertFrom-Json
        if ($j.name -eq 'mongodb') { O 'SW' 'npm-mongodb' 'host' $p $j.version '' '' '' '' }
      } else {
        O 'FILE' 'host' $p
      }
    }
  }
}
if ($cnt -gt 80) { O 'TRUNC' 'FIND' $cnt }

O 'END' ("{0}s" -f [int]((Get-Date) - $t0).TotalSeconds)
