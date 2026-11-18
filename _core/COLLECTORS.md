# 수집기 (scan_linux.sh, scan_windows.ps1)

대상 서버 안에서 실행되는 수집 스크립트입니다. 취약점과 무관하게 같은 스크립트를 쓰고, 판정은 `vsweep/`가 취약점 폴더의 기준표로 합니다.

| 파일 | 실행 환경 | 실행 경로 |
|---|---|---|
| scan_linux.sh | bash, root (Amazon Linux 2/2023, RHEL/CentOS 7 이상, Rocky, Ubuntu) | `run_ssm.sh`(AWS-RunShellScript), `run_bastion.sh`(sudo) |
| scan_windows.ps1 | Windows PowerShell 5.1, SYSTEM | `run_ssm.sh`(AWS-RunPowerShellScript) |

## 지켜야 할 것

- 읽기 전용입니다. 설치, 파일 쓰기, 설정 변경, 서비스 재기동을 넣지 않습니다.
- 실행해도 되는 명령은 조회와 버전 출력뿐입니다. 예: `java -version`, `mysqld --version`, `opatch lspatches`, `docker ps`
- CPU, I/O 우선순위를 최저로 낮추고 시작합니다. Linux는 `renice`, `ionice`, Windows는 Idle입니다.
- 출력은 SSM API 한도인 24,000자 안에 들어가야 합니다. 그래서 항목별로 줄 수 상한을 두었고, 넘치면 `TRUNC` 줄을 남깁니다.
- 프로세스 실행 인자에서는 jar 이름, `catalina.base` 같은 식별 정보만 남깁니다. pass, secret, token, key가 들어간 값은 버립니다.
- 마지막 줄은 반드시 `END`입니다. 러너는 이 줄로 끝까지 실행됐는지 판단합니다.
- 수집 항목을 바꾸면 `META collector` 버전 문자열을 올립니다.

## 출력 형식

한 줄이 레코드 하나이고 탭으로 구분합니다. 첫 필드가 레코드 종류입니다.

| 종류 | 필드 | 설명 |
|---|---|---|
| META | 키, 값 | collector, host, os, arch, cpu, avx512vbmi(Linux만) |
| PKG | 패키지명, 버전 | rpm/dpkg 또는 Windows Uninstall 레지스트리에서 이름이 jdk, jre, java, corretto, mysql, mariadb, oracle 등과 맞는 것 |
| PROC | pid, 사용자, comm, exe, 위치, release 정보, 식별 힌트, stale 표시 | libjvm.so/jvm.dll을 올린 모든 프로세스와 mysqld, mariadbd, tnslsnr, ora_pmon_*. 위치는 host 또는 컨테이너 cgroup. stale은 JDK 교체 후 미재기동(libjvm deleted) |
| SVC | 서비스명, 상태, exe | Windows 서비스 중 Java, Tomcat, MySQL, Oracle 계열 |
| PROCRUN | 서비스명, jvm.dll 경로, release 정보 | Windows procrun(Tomcat 등) 서비스의 JVM 설정 |
| OHOME | Oracle Home 경로, 소유자 | oraInventory, oratab, 레지스트리에 등록된 Home |
| OREG | Oracle Home, distribution 속성 | Home의 inventory/registry.xml (WebLogic, FMW 버전) |
| OPATCH | Oracle Home, 출력 줄 | `opatch lspatches`, 오래된 OPatch는 `lsinventory` 요약 |
| DOCKER | ps, 컨테이너명, 이미지, 상태 | 실행 중 컨테이너 |
| JAVA | 위치(host/image), 경로, release 정보, 버전 출력 | 디스크에서 찾은 java 바이너리. image는 컨테이너 이미지 레이어(실행하지 않고 release 파일만 읽음) |
| MYSQL | 위치, 경로, 버전 출력 | mysqld, mariadbd, mysql, mysqlsh |
| FILE | 위치, 경로 | weblogic.jar, helidon-*.jar, ords.war, VBoxManage |
| TRUNC | 종류, 위치, 전체 개수 | 상한 초과로 생략된 항목 |
| END | 소요 시간 | 완료 표시 |

## 탐지 대상을 늘릴 때

1. Linux는 FIND 구간의 `-path`, `-name` 패턴을, Windows는 `$names` 목록을 늘립니다.
2. 버전을 읽는 방법을 정합니다. 바이너리 버전 출력, 패키지 버전, 매니페스트 파일 등이 있습니다. 레코드 종류가 새로 필요하면 위 표에 추가합니다.
3. 새 레코드를 판정하는 코드를 `_core/vsweep/products.py`와 `_core/vsweep/judge.py`에 추가합니다.
4. 스캔 시간과 출력 길이가 늘지 않았는지 시범 서버 1대에서 확인합니다.
