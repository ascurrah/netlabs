#!/usr/bin/env bash

setup_pfsense() {
    echo -e "> Setting up Splunk Forwarder on pfSense ...\n"

    PFSENSE_IP=$1
    PFSENSE_CONF="/cf/conf/config.xml"
    USERNAME="root"
    PASSWORD="labadmin"

    SPLUNK_IP=$2
    SPLUNK_CONF_PATH="/opt/splunkforwarder/etc/system/local"""

    sshpass -p ${PASSWORD} ssh -o StrictHostKeyChecking=no ${USERNAME}@${PFSENSE_IP} << EOF
#!/bin/sh

curl -s http://localhost > /dev/null

cp "${PFSENSE_CONF}" "${PFSENSE_CONF}.bak"

sed -i "" "s|<remoteserver>.*</remoteserver>|<remoteserver>${SPLUNK_IP}:9997</remoteserver>|" "${PFSENSE_CONF}"

cp "${SPLUNK_CONF_PATH}/inputs.conf" "${SPLUNK_CONF_PATH}/inputs.conf.bak"
cp "${SPLUNK_CONF_PATH}/outputs.conf" "${SPLUNK_CONF_PATH}/outputs.conf.bak"

cat > "${SPLUNK_CONF_PATH}/inputs.conf" << "INPUTS_EOF"
[monitor:///var/log/suricata/suricata_em331133/eve.json]
sourcetype = suricata
disabled = 0
INPUTS_EOF

cat > "${SPLUNK_CONF_PATH}/outputs.conf" << "OUTPUTS_EOF"
[tcpout]
defaultGroup=my_indexers

[tcpout:my_indexers]
server=${SPLUNK_IP}:9997
OUTPUTS_EOF

cat > "${SPLUNK_CONF_PATH}/limits.conf" << "LIMITS_EOF"
[thruput]
maxKBps = 1024
LIMITS_EOF

: > /var/log/suricata/suricata_em331133/eve.json

/opt/splunkforwarder/bin/splunk restart
/etc/rc.reload_all
EOF

    echo -e "\n> Splunk Forwarder on pfSense Setup Complete!\n"
}

setup_splunk_server() {
    echo -e "> Setting up Splunk Server ...\n"

    SPLUNK_IP=$1

    SPLUNK_CONF="/opt/splunk/etc/system/local/inputs.conf"

    # backup config
    cp "${SPLUNK_CONF}" "${SPLUNK_CONF}.bak"

    cat << EOF > "${SPLUNK_CONF}"
[splunktcp://${SPLUNK_IP}:9997]
disabled = 0
sourcetype = suricata
connection_host = none
compressed = true
EOF
    # reload splunk input and output
    /opt/splunk/bin/splunk reload tcp udp

    echo -e "\n> Splunk Server Setup Complete!\n"
}

setup_metasploitable() {
    echo -e "> Setting up syslog on Metasploitable ...\n"

    METASPLOITABLE_IP=$1
    SPLUNK_IP=$2

    USERNAME="msfadmin"
    PASSWORD="msfadmin"
    SYSLOG_CONF="/etc/syslog.conf"

    REMOTE_SCRIPT=$(cat << EOF
#!/bin/bash

cp "${SYSLOG_CONF}" "${SYSLOG_CONF}.bak"

grep -qxF "*.* @${SPLUNK_IP}" "${SYSLOG_CONF}" || echo "*.* @${SPLUNK_IP}" >> "${SYSLOG_CONF}"

/etc/init.d/sysklogd restart
EOF
    )

    sshpass -p "${PASSWORD}" ssh -o StrictHostKeyChecking=no ${USERNAME}@${METASPLOITABLE_IP} "cat > run; chmod +x run" <<< "${REMOTE_SCRIPT}"

    sshpass -p "${PASSWORD}" ssh -o StrictHostKeyChecking=no ${USERNAME}@${METASPLOITABLE_IP} "echo ${PASSWORD} | sudo -S -p '' ./run; rm ./run"

    echo -e "\n> Syslog on Metasploitable Setup Complete!\n"
}

setup_blackbox() {
    echo -e "> Setting up syslog on Blackbox ...\n"

    BLACKBOX_IP=$1
    SPLUNK_IP=$2

    USERNAME="bobdabuilder"
    PASSWORD="iamblackbox"
    SYSLOG_CONF="/etc/rsyslog.conf"

    REMOTE_SCRIPT=$(cat << EOF
#!/bin/bash

cp "${SYSLOG_CONF}" "${SYSLOG_CONF}.bak"

grep -qxF "*.* @${SPLUNK_IP}" "${SYSLOG_CONF}" || echo "*.* @${SPLUNK_IP}" >> "${SYSLOG_CONF}"

systemctl restart rsyslog
EOF
    )

    sshpass -p "${PASSWORD}" ssh -p 2222 -o StrictHostKeyChecking=no ${USERNAME}@${BLACKBOX_IP} "cat > run; chmod +x run" <<< "${REMOTE_SCRIPT}"

    sshpass -p "${PASSWORD}" ssh -p 2222 -o StrictHostKeyChecking=no ${USERNAME}@${BLACKBOX_IP} "echo ${PASSWORD} | sudo -S -p '' ./run; rm ./run"

    echo -e "\n> Syslog on Blackbox Setup Complete!\n"
}

setup_init() {
    echo -e "> Setting up Local Machine ...\n"

    sudo apt update && sudo apt install -y sshpass

    echo -e "\n> Local Machine Setup Complete!\n"
}

main() {
    echo -e ">> Setting up Blue Team..."

    # usage
    if [ -z "$1" ]; then
        echo "usage: $0 <SPLUNK_IP>"
        exit 1
    fi

    SPLUNK_IP=$1
    PFSENSE_IP="192.168.0.1"
    METASPLOITABLE_IP="10.30.0.235"
    BLACKBOX_IP="10.30.0.250"

    setup_init
    setup_metasploitable "${METASPLOITABLE_IP}" "${SPLUNK_IP}"
    setup_blackbox "${BLACKBOX_IP}" "${SPLUNK_IP}"
    setup_pfsense "${PFSENSE_IP}" "${SPLUNK_IP}"
    setup_splunk_server "${SPLUNK_IP}"

    echo -e ">> Blue Team Setup Complete!\n"
}

main "$@"
