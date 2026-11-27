#!/bin/bash
# web-status.sh: state of the web stack of a host, before and after a change.
# Run by tasks/web_status.yml with ansible.builtin.script. Reads only.
#
#   web-status.sh [panel_port]
#
# One line per item, "kind|name|value":
#   service|apache2|active          apache2, nginx, mariadb, mysql, if installed
#   fpm|count|2                     running php*-fpm units (the version changes
#                                   with a release upgrade, so they're counted)
#   panel|8080|302                  HTTP code of the ISPConfig panel, if it listens
#   site|www.example.com|200        HTTP code of each ServerName in sites-enabled
#
# Codes come from curl against 127.0.0.1 with the site's name (--resolve, on
# 80 and 443), following redirects so a site that sends everything to https
# is checked there too. The check doesn't depend on DNS, except for a redirect
# to another name. 000 means no answer.

set -u
port="${1:-8080}"
export LC_ALL=C

for unit in apache2 nginx mariadb mysql; do
    if systemctl list-unit-files "${unit}.service" --no-legend 2>/dev/null | grep -q .; then
        echo "service|${unit}|$(systemctl is-active "${unit}.service" 2>/dev/null)"
    fi
done

fpm=$(systemctl list-units --type=service --state=running --plain --no-legend 'php*-fpm.service' 2>/dev/null | wc -l)
echo "fpm|count|${fpm}"

code() {
    curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$@" 2>/dev/null || true
}

if command -v ss >/dev/null && ss -ltnH "sport = :${port}" 2>/dev/null | grep -q .; then
    c=$(code -k "https://127.0.0.1:${port}/")
    [ "$c" = "000" ] && c=$(code "http://127.0.0.1:${port}/")
    echo "panel|${port}|${c}"
fi

# ServerName lines of enabled vhosts (Apache) and server_name (nginx); the
# ISPConfig panel vhost has none, and wildcard or regex names are skipped.
{
    cat /etc/apache2/sites-enabled/* 2>/dev/null | awk 'tolower($1)=="servername"{print $2}'
    cat /etc/nginx/sites-enabled/* 2>/dev/null \
        | awk 'tolower($1)=="server_name"{for(i=2;i<=NF;i++){gsub(";","",$i); print $i}}'
} | grep -E '^[A-Za-z0-9.-]+$' | grep -v '^_$' | sort -u | head -200 | while read -r name; do
    echo "site|${name}|$(code -k -L --max-redirs 5 --resolve "${name}:80:127.0.0.1" --resolve "${name}:443:127.0.0.1" "http://${name}/")"
done
exit 0
