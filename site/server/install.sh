#!/bin/sh
# One-time server setup. Run as root from the site/server/ folder: sudo sh install.sh
# Then point Apache's DocumentRoot to /var/www/offsecnotes (dedicated folder:
# anything else in it gets deleted on every sync) and serve it as plain files:
#   <Directory /var/www/offsecnotes>
#     Options None
#     AllowOverride None
#     Require all granted
#   </Directory>
# (no PHP/CGI handlers on this vhost).
set -eu
cd "$(dirname "$0")"

command -v git >/dev/null || apt-get install -y git
id offsecnotes >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin offsecnotes
install -d -o offsecnotes -g offsecnotes -m 755 /var/www/offsecnotes

install -m 755 offsecnotes-sync.sh /usr/local/bin/offsecnotes-sync
install -m 644 offsecnotes-sync.service offsecnotes-sync.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now offsecnotes-sync.timer
systemctl start offsecnotes-sync.service

echo "OK: $(ls /var/www/offsecnotes | wc -l) entries in /var/www/offsecnotes"
