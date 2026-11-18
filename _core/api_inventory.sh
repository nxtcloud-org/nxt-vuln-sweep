#!/usr/bin/env bash
# 1단계: AWS API 자산 조회 (읽기 전용, describe/list 호출만 사용)
# 보통 _core/sweep inventory <고객> <취약점ID> 로 실행한다. 직접 실행: _core/api_inventory.sh <RUN_DIR>
#   RUN_DIR = $SWEEP_RUNS/<고객>/<취약점ID>  (리포 밖)
#   RUN_DIR/../config.env 의 AWS_PROFILE, AWS_REGION 을 읽는다. REGIONS 를 지정하면 그 리전만 조회한다.
# 출력: RUN_DIR/api/<리전>/{ec2,ssm,rds,rds_clusters,lambda,ecr,ecs,eks,beanstalk,inspector}.json, lb_targets.tsv, ecr_images.tsv
set -u
RUN_DIR=$(cd "${1:?RUN_DIR 필요}" && pwd) || exit 1
CORE=$(cd "$(dirname "$0")" && pwd)
if [ -f "$RUN_DIR/../config.env" ]; then set -a; . "$RUN_DIR/../config.env"; set +a; fi
export AWS_PAGER=""
HOME_REGION=${AWS_REGION:-ap-northeast-2}
OUT="$RUN_DIR/api"; mkdir -p "$OUT"

if ! aws sts get-caller-identity --region "$HOME_REGION" --output json > "$OUT/identity.json"; then
  echo "AWS 자격증명 확인 실패. SSO 프로파일이면 사용자에게 'aws sso login --profile ${AWS_PROFILE:-<프로파일>}' 실행을 요청할 것" >&2
  exit 1
fi
REGIONS=${REGIONS:-$(aws ec2 describe-regions --region "$HOME_REGION" --query 'Regions[].RegionName' --output text)}

scan_region() {
  local r=$1 d="$OUT/$1"
  mkdir -p "$d"
  aws ec2 describe-instances --region "$r" --output json \
    --query 'Reservations[].Instances[].{id:InstanceId,name:Tags[?Key==`Name`]|[0].Value,state:State.Name,type:InstanceType,arch:Architecture,platform:PlatformDetails,privateIp:PrivateIpAddress,publicIp:PublicIpAddress,ami:ImageId,key:KeyName,launch:LaunchTime,profile:IamInstanceProfile.Arn}' \
    > "$d/ec2.json" 2> "$d/ec2.err"
  aws ssm describe-instance-information --region "$r" --output json \
    --query 'InstanceInformationList[].{id:InstanceId,ping:PingStatus,os:PlatformName,osver:PlatformVersion,agent:AgentVersion,host:ComputerName}' \
    > "$d/ssm.json" 2> "$d/ssm.err"
  aws rds describe-db-instances --region "$r" --output json \
    --query 'DBInstances[].{id:DBInstanceIdentifier,engine:Engine,ver:EngineVersion,cls:DBInstanceClass,status:DBInstanceStatus,autoMinor:AutoMinorVersionUpgrade,public:PubliclyAccessible,cluster:DBClusterIdentifier}' \
    > "$d/rds.json" 2> "$d/rds.err"
  aws rds describe-db-clusters --region "$r" --output json \
    --query 'DBClusters[].{id:DBClusterIdentifier,engine:Engine,ver:EngineVersion,status:Status}' > "$d/rds_clusters.json" 2> "$d/rds_clusters.err"
  aws lambda list-functions --region "$r" --output json \
    --query 'Functions[].{name:FunctionName,runtime:Runtime,pkg:PackageType,arch:Architectures}' > "$d/lambda.json" 2> "$d/lambda.err"
  aws ecr describe-repositories --region "$r" --output json --query 'repositories[].repositoryName' > "$d/ecr.json" 2> "$d/ecr.err"
  aws ecs list-clusters --region "$r" --output json --query 'clusterArns' > "$d/ecs.json" 2> "$d/ecs.err"
  aws eks list-clusters --region "$r" --output json --query 'clusters' > "$d/eks.json" 2> "$d/eks.err"
  aws elasticbeanstalk describe-environments --region "$r" --output json \
    --query 'Environments[].{name:EnvironmentName,stack:SolutionStackName,platform:PlatformArn,status:Status}' > "$d/beanstalk.json" 2> "$d/beanstalk.err"
  aws inspector2 batch-get-account-status --region "$r" --output json --query 'accounts[].resourceState' > "$d/inspector.json" 2> "$d/inspector.err"

  # 로드밸런서 대상 (외부 노출 판단용): LB이름, scheme, 유형, 대상그룹, 대상ID, 포트, 상태
  aws elbv2 describe-load-balancers --region "$r" --query 'LoadBalancers[].[LoadBalancerArn,LoadBalancerName,Scheme,Type]' --output text 2> "$d/elbv2.err" |
    while read -r arn name scheme type; do
      [ -n "${arn:-}" ] || continue
      for tg in $(aws elbv2 describe-target-groups --region "$r" --load-balancer-arn "$arn" --query 'TargetGroups[].TargetGroupArn' --output text); do
        aws elbv2 describe-target-health --region "$r" --target-group-arn "$tg" --query 'TargetHealthDescriptions[].[Target.Id,Target.Port,TargetHealth.State]' --output text |
          while read -r tid port st; do
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$scheme" "$type" "$(basename "$(dirname "$tg")")" "$tid" "$port" "$st"
          done
      done
    done > "$d/lb_targets.tsv"

  # ECR 이미지 메타데이터 (이미지 자체는 내려받지 않음)
  python3 -c 'import json,sys; [print(x) for x in (json.load(open(sys.argv[1])) or [])]' "$d/ecr.json" 2>/dev/null |
    while read -r repo; do
      aws ecr describe-images --region "$r" --repository-name "$repo" --output text \
        --query 'imageDetails[].[repositoryName,join(`,`,imageTags||[`<untagged>`]),imagePushedAt,lastRecordedPullTime]'
    done > "$d/ecr_images.tsv" 2> "$d/ecr_images.err"
}

for r in $REGIONS; do scan_region "$r" & done
wait
date -u +%FT%TZ > "$OUT/collected_at.txt"
echo "자산 조회 완료: $OUT"
cd "$CORE" && python3 -m vsweep.targets "$RUN_DIR"
