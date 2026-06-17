#!/bin/bash
# ============================================================
#  哪吒面板入侵 自查+清理脚本 (nezha_ioc_check.sh)
# ------------------------------------------------------------
#  用途:排查 2026-06 哪吒面板漏洞批量入侵的常见植入物
#  特点:发现后按规则执行清理,并输出清理日志
#  用法:直接在被检查的服务器上执行  bash nezha_ioc_check.sh
#        或从本地批量: ssh 节点 'bash -s' < nezha_ioc_check.sh
# ------------------------------------------------------------
#  注意:脚本会停止/删除命中的恶意进程、文件、systemd/cron 持久化。
#  由于已被 root 控制过,彻底安全仍建议后续更换凭据并重装系统。
# ============================================================

ALERT=0
CHANGED=0
LOG="/root/nezha_ioc_cleanup_$(date +%F_%H%M%S).log"
touch "$LOG"

log() {
  echo "$*" | tee -a "$LOG"
}

do_run() {
  log "    [清理] $*"
  "$@" >>"$LOG" 2>&1 || true
  CHANGED=1
}

remove_path() {
  local path="$1"
  [ -e "$path" ] || return 0
  log "    [清理] 删除 $path"
  rm -rf -- "$path" >>"$LOG" 2>&1 || true
  CHANGED=1
}

stop_disable_service() {
  local svc="$1"
  systemctl stop "$svc" >>"$LOG" 2>&1 || true
  systemctl disable "$svc" >>"$LOG" 2>&1 || true
  CHANGED=1
}

clean_line_in_file() {
  local file="$1"
  local pattern="$2"
  [ -f "$file" ] || return 0
  if grep -qE "$pattern" "$file" 2>/dev/null; then
    log "    [清理] 清理文件 $file 中的可疑行"
    sed -i "/$pattern/d" "$file" >>"$LOG" 2>&1 || true
    CHANGED=1
  fi
}
log "=========================================="
log " 哪吒入侵自查+清理: $(hostname)  $(date '+%F %T')"
log " 日志文件: $LOG"
log "=========================================="

# ---- 1) memfd 内存马 ----
# 攻击者用 memfd_create 把恶意程序只放在内存、磁盘无文件,
# 常伪装成 [kworker/x:x]。靠 /proc/PID/exe 指向 memfd 识别。
log "[1] memfd 内存马"
for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
  if ls -l /proc/$pid/exe 2>/dev/null | grep -qi "memfd"; then
    log "  [警] PID $pid 指向 memfd  cmd=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')"
    do_run kill -STOP "$pid"
    do_run kill -9 "$pid"
    ALERT=1
  fi
done

# ---- 2) kworker 伪装(进程名像内核线程,却有用户态 exe)----
# 真内核线程父进程是 kthreadd(PID 2)且无 exe;伪装的则有真实 exe。
# 注:请把下面 EXCLUDE 里换成你自己合法的、恰好以 k 开头的程序名(如 komari)。
EXCLUDE_COMM="kdump|komari|kubelet"
log "[2] kworker 伪装进程"
for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
  comm=$(cat /proc/$pid/comm 2>/dev/null)
  exe=$(readlink /proc/$pid/exe 2>/dev/null)
  ppid=$(awk '{print $4}' /proc/$pid/stat 2>/dev/null)
  case "$comm" in
    k*)
      if [ -n "$exe" ] && [ "$ppid" != "2" ]; then
        if ! echo "$comm" | grep -qE "^($EXCLUDE_COMM)" && [ "${exe#*/usr/lib/systemd/}" = "$exe" ]; then
          log "  [警] PID $pid 进程名=$comm 父=$ppid exe=$exe"
          do_run kill -STOP "$pid"
          do_run kill -9 "$pid"
          case "$exe" in
            /tmp/*|/var/tmp/*|/dev/shm/*|/root/*|/home/*|/opt/*)
              remove_path "${exe%% *}"
              ;;
          esac
          ALERT=1
        fi
      fi
      ;;
  esac
done

# ---- 3) 执行已删除文件的进程((deleted))----
# 程序跑起来后删掉自身文件,只留内存副本。排除正常软件路径与升级残留。
# 注:把 /app 换成你自己正常程序所在目录,避免误报。
log "[3] 已删除文件执行"
for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
  exe=$(readlink /proc/$pid/exe 2>/dev/null)
  case "$exe" in
    *"(deleted)"*)
      case "$exe" in
        */usr/*|*/bin/*|*/sbin/*|*/app/*|*/snap/*) ;;
        *)
          log "  [警] PID $pid exe=$exe"
          do_run kill -STOP "$pid"
          do_run kill -9 "$pid"
          ALERT=1
          ;;
      esac
      ;;
  esac
done

# ---- 4) 恶意哪吒 Agent(随机后缀 config / service,连第三方主控)----
log "[4] 恶意哪吒 Agent 残留"
ps aux | grep -i 'nezha-agent' | grep -v grep | grep -E 'config-[a-z0-9]+\.yml' \
  && {
    log "  [警] 发现随机后缀 config 的 agent 进程"
    do_run pkill -STOP -f 'nezha-agent.*config-[a-z0-9]+\.yml'
    do_run pkill -9 -f 'nezha-agent.*config-[a-z0-9]+\.yml'
    ALERT=1
  }
for svc in $(ls /etc/systemd/system/ 2>/dev/null | grep -E 'nezha-agent-[a-z0-9]+\.service' || true); do
  log "  [警] 发现随机后缀 nezha service: $svc"
  stop_disable_service "$svc"
  remove_path "/etc/systemd/system/$svc"
  ALERT=1
done
for cfg in $(ls /opt/nezha/agent/config-*.yml 2>/dev/null || true); do
  log "  [警] 发现随机 config 文件: $cfg"
  remove_path "$cfg"
  ALERT=1
done

# ---- 5) 挖矿程序(XMRig / c3pool)----
log "[5] 挖矿程序"
[ -e /root/c3pool ] && { log "  [警] /root/c3pool 目录存在"; remove_path /root/c3pool; ALERT=1; }
if pgrep -x xmrig >/dev/null 2>&1; then
  log "  [警] xmrig 进程在运行"
  do_run pkill -STOP -x xmrig
  do_run pkill -9 -x xmrig
  ALERT=1
fi
[ -e /etc/systemd/system/c3pool_miner.service ] && {
  log "  [警] c3pool_miner.service 存在"
  stop_disable_service c3pool_miner.service
  remove_path /etc/systemd/system/c3pool_miner.service
  remove_path /etc/systemd/system/multi-user.target.wants/c3pool_miner.service
  ALERT=1
}

# ---- 6) 守护/复活服务(SystemLoger / systemlog.service)----
log "[6] 守护/复活服务"
if pgrep -x SystemLoger >/dev/null 2>&1; then
  log "  [警] SystemLoger 进程在运行"
  do_run pkill -STOP -x SystemLoger
  do_run pkill -9 -x SystemLoger
  ALERT=1
fi
[ -e /opt/systemlog ] && { log "  [警] /opt/systemlog 目录存在"; remove_path /opt/systemlog; ALERT=1; }
[ -e /etc/systemd/system/systemlog.service ] && {
  log "  [警] systemlog.service 存在"
  stop_disable_service systemlog.service
  remove_path /etc/systemd/system/systemlog.service
  remove_path /etc/systemd/system/multi-user.target.wants/systemlog.service
  ALERT=1
}

# ---- 7) SSH 后门公钥 ----
# 网传后门公钥常带 gary 之类注释;这里同时提示你核对公钥总数。
log "[7] SSH 后门公钥"
grep -i "gary" ~/.ssh/authorized_keys 2>/dev/null \
  && {
    log "  [警] authorized_keys 含可疑公钥(gary)"
    if [ -f ~/.ssh/authorized_keys ]; then
      cp ~/.ssh/authorized_keys ~/.ssh/authorized_keys.bak.$(date +%F_%H%M%S) >>"$LOG" 2>&1 || true
      sed -i '/gary/Id' ~/.ssh/authorized_keys >>"$LOG" 2>&1 || true
      CHANGED=1
    fi
    ALERT=1
  }
log "  (当前 authorized_keys 公钥数: $(grep -c '^ssh-' ~/.ssh/authorized_keys 2>/dev/null))"

# ---- 8) 自启动持久化(cron / 可疑 service)----
log "[8] 持久化(cron)"
for u in $(cut -f1 -d: /etc/passwd); do
  c=$(crontab -l -u "$u" 2>/dev/null | grep -vE '^\s*#|^\s*$')
  [ -n "$c" ] && { log "  [信息] 用户 $u 有 cron(请核对):"; echo "$c" | sed 's/^/      /' | tee -a "$LOG"; }
done
grep -rEl 'curl|wget|/tmp/|base64 -d' /etc/cron* /var/spool/cron 2>/dev/null \
  | while read -r f; do
      [ -n "$f" ] || continue
      log "  [警] cron 文件含可疑下载/执行: $f"
      clean_line_in_file "$f" 'curl|wget|/tmp/|base64 -d|xmrig|c3pool|monero|stratum|SystemLoger|systemlog'
      ALERT=1
    done

for f in /etc/rc.local /root/.bashrc /root/.profile /root/.bash_profile /etc/profile; do
  clean_line_in_file "$f" 'xmrig|c3pool|monero|stratum|SystemLoger|systemlog|curl .*sh|wget .*sh'
done

# ---- 9) ld.so.preload 劫持 ----
log "[9] ld.so.preload"
[ -f /etc/ld.so.preload ] && {
  log "  [警] /etc/ld.so.preload 存在(默认不该有):"
  cat /etc/ld.so.preload | sed 's/^/      /' | tee -a "$LOG"
  cp /etc/ld.so.preload "/root/ld.so.preload.bak.$(date +%F_%H%M%S)" >>"$LOG" 2>&1 || true
  : > /etc/ld.so.preload
  CHANGED=1
  ALERT=1
}

log "[10] 额外通杀清理"
for svc in c3pool_miner.service systemlog.service; do
  [ -e "/etc/systemd/system/$svc" ] || continue
  stop_disable_service "$svc"
  remove_path "/etc/systemd/system/$svc"
done
for p in /tmp/c3pool /var/tmp/c3pool /dev/shm/c3pool /opt/c3pool /usr/local/c3pool; do
  remove_path "$p"
done
systemctl daemon-reload >>"$LOG" 2>&1 || true

# ---- 结论 ----
log "=========================================="
if [ "$ALERT" -eq 0 ]; then
  log " 结论: 未发现已知植入物 ✅ (但不代表绝对安全,被 root 控制过仍建议重装)"
else
  log " 结论: 发现 [警] 项并已尝试自动清理 ⚠️"
fi
if [ "$CHANGED" -eq 1 ]; then
  log " 已执行清理动作,建议复查: ps auxww | egrep -i 'xmrig|c3pool|SystemLoger|nezha-agent|kdevtmpfsi|kinsing'"
fi
log "=========================================="

