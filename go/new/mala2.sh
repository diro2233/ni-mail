#!/bin/bash

# --- 1. 初始化随机密码与文件名 ---
RAND_PWD=$(shuf -i 100000-999999 -n 1)
TIMESTAMP=$(date +%Y%m%d)
BACKUP_DIR="/root/malware_cases_${TIMESTAMP}"
ZIP_NAME="/root/virus_pwd_HIDDEN_${TIMESTAMP}.zip"
LOG_FILE="/root/surgical_fix_${TIMESTAMP}.log"

mkdir -p "$BACKUP_DIR"

echo "==================================================" | tee -a "$LOG_FILE"
echo "[*] 脚本启动时间: $(date)" | tee -a "$LOG_FILE"
echo "[*] 本次打包随机密码为: ${RAND_PWD}" | tee -a "$LOG_FILE"
echo "==================================================" | tee -a "$LOG_FILE"

# --- 2. 停用并删除恶意的 nezha-agent-<随机数> 服务 ---
echo "[1/5] 开始排查异常 Nezha 服务..." | tee -a "$LOG_FILE"
for svc_file in $(ls /etc/systemd/system/nezha-agent-*.service 2>/dev/null); do
    svc_name=$(basename "$svc_file")
    echo "发现恶意服务文件: ${svc_file}，正在终止并删除..." | tee -a "$LOG_FILE"
    
    cp "$svc_file" "$BACKUP_DIR/"
    systemctl stop "$svc_name" >> "$LOG_FILE" 2>&1
    systemctl disable "$svc_name" >> "$LOG_FILE" 2>&1
    rm -f "$svc_file"
done
systemctl daemon-reload

# --- 3. 从 /opt/nezha/agent/ 中清除最近产生及异常文件 ---
echo "[2/5] 开始清理 /opt/nezha/agent/ 目录..." | tee -a "$LOG_FILE"
if [ -d "/opt/nezha/agent" ]; then
    cd /opt/nezha/agent/ || exit
    
    for bad_file in config-*.yml nohup.out agent.sh; do
        if [ -f "$bad_file" ]; then
            echo "备份并删除已知恶意文件: $bad_file" | tee -a "$LOG_FILE"
            cp "$bad_file" "$BACKUP_DIR/"
            rm -f "$bad_file"
        fi
    done
    
    find . -type f -mtime -3 | while read -r recent_file; do
        if [[ "$recent_file" != "./config.yml" && "$recent_file" != "./nezha-agent" ]]; then
            echo "发现近期修改的嫌疑文件: $recent_file，移至备份区..." | tee -a "$LOG_FILE"
            cp --parents "$recent_file" "$BACKUP_DIR/"
            rm -f "$recent_file"
        fi
    done
fi

# --- 4. 从 crontab 中精准提取恶意应用名称并强杀 ---
echo "[3/5] 正在从 crontab 抓取底牌路径..." | tee -a "$LOG_FILE"
crontab -l > "$BACKUP_DIR/crontab_original.bak" 2>/dev/null

# 提取绝对路径
MALICIOUS_PATHS=$(crontab -l 2>/dev/null | grep "pgrep" | grep "/dev/shm/" | grep -oE '/dev/shm/[^ >&]+' | sort -u)

if [ -z "$MALICIOUS_PATHS" ]; then
    echo "警告: 未能从 crontab 中通过特征提取到路径，转为全盘复合特征扫描..." | tee -a "$LOG_FILE"
    MALICIOUS_PATHS=$(find /dev/shm/ -type f -name ".*" 2>/dev/null)
fi

for path in $MALICIOUS_PATHS; do
    echo "【成功定位】木马真实物理路径: $path" | tee -a "$LOG_FILE"
    
    PIDS=$(ps auxww | grep -F "$path" | grep -v "grep" | awk '{print $2}')
    if [ -n "$PIDS" ]; then
        for pid in $PIDS; do
            echo "正在采集进程内存映像 (PID: $pid)..." | tee -a "$LOG_FILE"
            cp "/proc/$pid/exe" "$BACKUP_DIR/proc_dump_${pid}" 2>/dev/null
            echo "强制结束恶意进程 PID: $pid" | tee -a "$LOG_FILE"
            kill -9 "$pid" >> "$LOG_FILE" 2>&1
        done
    fi
    
    if [ -f "$path" ]; then
        echo "正在复制木马实体供取证..." | tee -a "$LOG_FILE"
        cp "$path" "$BACKUP_DIR/malware_entity_$(basename "$path")"
        rm -f "$path"
    fi
done

# --- 5. 清空恶意定时任务 ---
echo "[4/5] 正在清空木马守护定时任务..." | tee -a "$LOG_FILE"
crontab -l 2>/dev/null | grep -v "pgrep" | grep -v "/dev/shm/" > /tmp/cron_clean.txt
crontab /tmp/cron_clean.txt
rm -f /tmp/cron_clean.txt

# --- 6. 最终打包加密与权限收尾 ---
echo "[5/5] 正在打包取证文件并收尾..." | tee -a "$LOG_FILE"
chmod 755 / && chown root:root /

if ! command -v zip &> /dev/null; then
    apt-get update && apt-get install zip -y >> "$LOG_FILE" 2>&1
fi

if command -v zip &> /dev/null; then
    cd "$BACKUP_DIR" || exit
    zip -r -P "${RAND_PWD}" "$ZIP_NAME" ./* >> "$LOG_FILE" 2>&1
    echo "==================================================" | tee -a "$LOG_FILE"
    echo "[+] 成功！所有恶意样本已安全隔离并打包至: $ZIP_NAME" | tee -a "$LOG_FILE"
    echo "[+] 解压密码为: ${RAND_PWD}" | tee -a "$LOG_FILE"
    echo "==================================================" | tee -a "$LOG_FILE"
    rm -rf "$BACKUP_DIR"
else
    echo "[-] 错误: 系统未安装 zip 且无法自动安装，请手动打包 ${BACKUP_DIR}" | tee -a "$LOG_FILE"
fi
