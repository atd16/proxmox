#!/bin/bash
#### Description: Proxmox Postinstallation + hardenning system
#### Written by: Yann Bogdanovic <ybogdanovic@atd16.fr> on 02/2019

#Variables
ERROR=" "
NEEDREBOOT=0

DANGER='\033[0;31m'
SUCCESS='\033[0;32m'
WARNING='\033[0;33m'
INFO='\033[0;34m'
NC='\033[0m' # No Color

#############################
#Menu options
# PROXMOX
options[0]="Post install de PROXMOX"
# SECURITE
options[1]="Durcir SSH - changement port et politique accès "
options[2]="Installer Lynis - Audit de sécurité (HIPAA/ISO27001/PCI DSS)"
options[3]="Installer rkhunter - détection de rootkit"
options[4]="Installer chkrootkit - détection de rootkit"
options[5]="Installer suricat - Detection d'intrusion"
# SUPERVISION
options[6]="Installer capteur PRTG - supervision"
# ANTIVIRUS
options[7]="Installer ClamAV - Antivirus"

#Actions to take based on selection
function ACTIONS {
  if [[ ${choices[0]} ]]; then
    echo -e "${INFO} Veuillez répondre aux questions suivantes ${NC}"
    # Mail des admins
    echo "Adresse mail de supervision:"
    read -r adminmail

    # Gestion du proxy local
    read -r -p "Aves-vous un proxy local ? <Y/n> " prompt
    if [[ $prompt == "y" || $prompt == "Y" || $prompt == "yes" || $prompt == "Yes" ]]
    then
      echo "IP du Proxy local"
      read -r proxy
    else
      echo "ok pas de proxy local"
      noproxy=1
    fi


    ##domaine smtp
    echo "Votre domaine d'émission smtp :"
    read -r domainesmtp

    ##relay smtp
    echo "Votre relay smtp :"
    read -r relaysmtp

    echo "Vos réponses :"
    echo "votre mail :" "$adminmail";
    echo "votre proxy :" "$proxy";
    echo "votre domaine smtp :" "$domainesmtp";
    echo "votre relay smtp :" "$relaysmtp";
    echo -e "${INFO} Mise a jour du serveur Proxmox ${NC}"


    ##conf proxy pour wget at apt
    if [[ "$noproxy" != "1" ]];
    then
      sed -i 's/proxy\.yoyodyne\.com\:18023/'"$proxy"':8080/g' /etc/wgetrc
      sed -i 's/\#https\_proxy/https\_proxy/g' /etc/wgetrc
      sed -i 's/\#http\_proxy/http\_proxy/g' /etc/wgetrc
      sed -i 's/\#ftp\_proxy/ftp\_proxy/g' /etc/wgetrc
      sed -i 's/\#use\_proxy/use\_proxy/g' /etc/wgetrc

      touch /etc/apt/apt.conf
      echo 'Acquire::http::Proxy "http://proxy:8080/";' > /etc/apt/apt.conf
      sed -i 's/proxy/'"$proxy"'/g' /etc/apt/apt.conf
    fi

    # no-free apt
    echo -e "${INFO} Mise a jour des sources apt ${NC}"
    grep 'non-free' /etc/apt/sources.list
    if [ $? = "1" ]
    then
      sed -i "s/main/main\\ non-free/g" /etc/apt/sources.list
    else
      echo "non-free existant"
    fi

    # MAJ
    echo
    apt update && apt -y full-upgrade && apt -y dist-upgrade
    apt install -q -y pigz htop iptraf iotop iftop snmpd ntp ncdu ethtool snmp-mibs-downloader apticron --force-yes

    # ajout du serveur ntp
    echo -e "${INFO} Ajout du serveur NTP ${NC}"
    sed -i '/^#NTP/ s/#NTP=.*/NTP='"0.fr.pool.ntp.org"'/g' /etc/systemd/timesyncd.conf
    apt -y purge ntp
    systemctl restart systemd-timesyncd
    timedatectl set-ntp true
    echo -e "${SUCCESS} \u2714 Nouveau serveur ntp OK ${NC}"

    # remplacement de gzip par pigz
    # pour pigz, je lui attribu que le nombre de tread par cpu
    echo -e "${INFO} Remplacement de gzip par pigz ${NC}"
    touch /bin/pigzwrapper
    echo '#!/bin/sh' > /bin/pigzwrapper
    echo "PATH=${GZIP_BINDIR-'/bin'}:$PATH" >> /bin/pigzwrapper
    echo 'GZIP="-1"' >> /bin/pigzwrapper
    cpu=$(echo "$(grep -c "processor" /proc/cpuinfo) / $(grep "physical id" /proc/cpuinfo |sort -u |wc -l)" | bc)
    echo 'exec /usr/bin/pigz -p cpu  "$@"'  >> /bin/pigzwrapper
    sed -i 's/cpu/'"$cpu"'/g' /bin/pigzwrapper
    chmod +x /bin/pigzwrapper
    mv /bin/gzip /bin/gzip.original
    cp /bin/pigzwrapper /bin/gzip
    echo -e "${SUCCESS} \u2714 pigz remplace gzip ${NC}"

    # paramétrage de postfix
    echo -e "${INFO} Paramétrage de postfix ${NC}"
    postconf -e "relayhost=${relaysmtp}"
    postconf -e "myhostname=${domainesmtp}"
    postconf -e "inet_protocols = ipv4"
    postfix reload
    echo -e "${SUCCESS} \u2714 postfix paramétré ${NC}"

    # Paramétrage du apticron
    echo -e "${INFO}Ajout pour apticron de la boite mail de l'admin ${NC}"
    sed -i 's/root/'"$adminmail"'/g' /etc/apticron/apticron.conf

    # Envoi de mail avec le nom et l'IP du nouveau serveur PVE
    hostname -f > info.txt
    hostname -i >> info.txt
    echo "Mettre en supervision ce nouveau serveur Proxmox :" | mail -s "Nouveau Serveur Proxmox" "$adminmail" < info.txt
    echo -e "${SUCCESS} \u2714 Mail envoyé à $adminmail ${NC}"

    # modification du bashrc pour notification de connexion ssh avec l'history
    echo -e "echo \"Avertissement! Connexion au serveur : \" \`hostname\` \"par: \" \`who | grep -v localhost\` | mail -s \"[ \`hostname\` ] Avertissement!!! connexion au serveur le: \`date +'%Y/%m/%d'\`  \`who | grep -v localhost | awk {'print $5'}\`\" $adminmail -a \"From: `hostname`@$domainsmtp\"" >> /etc/bash.bashrc
    echo -e "PROMPT_COMMAND='history -a >(logger -t \"\$USER[\$PWD] \$SSH_CONNECTION\")'" >> /etc/bash.bashrc
    echo -e "${SUCCESS} \u2714 Notification par mail à chaque connexion ssh ${NC}"a

    echo -e "alias rm='rm -i'" >> /etc/bash.bashrc
    echo -e "${SUCCESS} \u2714 Commande rm avec confirmation ${NC}"

    NEEDREBOOT=1
  fi
  if [[ ${choices[1]} ]]; then
    #Option 1 selected
    echo -e "${INFO}Durcissement SSH${NC}"
    echo -e "${INFO}Ajout d'un utilisateur par défaut pour les connexions ssh : "
    PASSWORD=`openssl rand -base64 14`
    echo "${PASSWORD}" > mdp
    echo -e "${DANGER}Le mot de passe de \033[1molmec\033[0m est \033[1m${PASSWORD}\033[0m${NC}"
    echo -e "vous trouverez le mot de passe dans le fichier mdp"
    read -n 1 -s -r -p "Appuyez sur une touche pour continuer"
    useradd -p $(openssl passwd -1 $PASSWORD) olmec
    echo
    apt update
    apt install -q -y  augeas-tools

    augtool << EOF
set /files/etc/ssh/sshd_config/Port 10943
set /files/etc/ssh/sshd_config/Protocol 2
set /files/etc/ssh/sshd_config/UsePrivilegeSeparation yes
set /files/etc/ssh/sshd_config/KeyRegenerationInterval 3600
set /files/etc/ssh/sshd_config/ServerKeyBits 1024
set /files/etc/ssh/sshd_config/SyslogFacility AUTH
set /files/etc/ssh/sshd_config/LogLevel INFO
set /files/etc/ssh/sshd_config/LoginGraceTime 120
set /files/etc/ssh/sshd_config/PermitRootLogin no
set /files/etc/ssh/sshd_config/AllowUsers olmec
set /files/etc/ssh/sshd_config/StrictMode yes
set /files/etc/ssh/sshd_config/RSAAuthentication yes
set /files/etc/ssh/sshd_config/PubkeyAuthentication yes
set /files/etc/ssh/sshd_config/IgnoreRhosts yes
set /files/etc/ssh/sshd_config/RhostsRSAAuthentication no
set /files/etc/ssh/sshd_config/HostbasedAuthentication no
set /files/etc/ssh/sshd_config/ChallengeResponseAuthentication no
set /files/etc/ssh/sshd_config/PasswordAuthentication no
set /files/etc/ssh/sshd_config/PermitEmptyPasswords no
set /files/etc/ssh/sshd_config/ChallengeResponseAuthentication no
set /files/etc/ssh/sshd_config/X11DisplayOffset 10
set /files/etc/ssh/sshd_config/PrintLastLog yes
set /files/etc/ssh/sshd_config/TCPKeepAlive yes
set /files/etc/ssh/sshd_config/UsePAM yes

save
EOF
    service ssh restart
    echo -e "${SUCCESS} \u2714 Durcissement du ssh presque terminé.${NC}"
    echo -e "${WARNING}Décommenter les Hostkey dans /etc/ssh/sshd_config puis redémarrer le service : service ssh restart${NC}"

  fi
  if [[ ${choices[2]} ]]; then
    # Installation et configuration de lynis.
    echo -e "${INFO}Installation de lynis${NC}"
    echo
    apt install -q -y dirmngr apt-transport-https
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys C80E383C3DE9F082E01391A0366C67DE91CA5D5F
    echo 'Acquire::Languages "none";' | tee /etc/apt/apt.conf.d/99disable-translations
    echo "deb https://packages.cisofy.com/community/lynis/deb/ stable main" | tee /etc/apt/sources.list.d/cisofy-lynis.list
    echo
    apt update
    apt install -q -y lynis
    lynis audit system --quick


    if [ -z "$adminmail" ]; then
      read -p "Veuillez entrer votre adresse courriel pour recevoir les alertes : " adminmail
      read -p "Votre domaine d'émission smtp :" domainesmtp
    fi

    echo -e "${INFO} Mise en place d'un scan quotidien ${NC}"
    cat <<EOF > /root/lynis_daily.sh
#!/bin/bash
LOGFILE="/var/log/lynis.log";
EMAIL_MSG="Rapport lynis pour serveur ${HOSTNAME}.";
EMAIL_FROM="lynis-daily@${domainesmtp}";
EMAIL_TO="${adminmail}";

# Verification que l'on soit toujours à 100%
grep -q 'Hardening index : \\[100\\]' /var/log/lynis.log

# si ce n'est pas le cas, un mail
if [ \$? != 0 ]; then
  lynis update check | mail -a "\$LOGFILE" -s 'lynis report' -a "From: \$EMAIL_FROM" "\$EMAIL_TO"
fi

# envoi mail si nouvelle version
lynis update check > /tmp/lynis.check
if [ \$? != 0 ]; then
  lynis update info | mail -s 'lynis update available' -a "From: \$EMAIL_FROM" "\$EMAIL_TO"
fi
rm /tmp/lynis.check

exit 0
EOF
    chmod 0755 /root/lynis_daily.sh
    ln /root/lynis_daily.sh /etc/cron.daily/lynis_daily

    echo -e "${SUCCESS} \u2714 Installation et configuration de lynis terminée.${NC}"
  fi
  if [[ ${choices[3]} ]]; then
    # Installation et configuration de rkhunter.
    echo -e "${INFO}Installation de rkhunter${NC}"
    if [ -z "$adminmail" ]; then
      read -p "Veuillez entrer votre adresse courriel pour recevoir les alertes : " adminmail
      read -p "Votre domaine d'émission smtp :" domainesmtp
    fi
    apt install -q -y rkhunter
    # Créer la base de données
    rkhunter --propupd

    sed -i "s/^MAIL-ON-WARNING=.*/#MAIL-ON-WARNING=/g" /etc/rkhunter.conf
    sed -i "s/^#MAIL-ON-WARNING=.*/MAIL-ON-WARNING=$adminmail/" /etc/rkhunter.conf

    echo "Scan quotidien, à 4h il effectue la vérification du système et envoi une alerte s'il trouve quelque chose."
    crontab -l > mycron
    echo "0 4 * * * /usr/bin/rkhunter --cronjob --update --quiet" >> mycron
    crontab mycron

    echo -e "${INFO}Scan le système${NC}"
    rkhunter --checkall --quiet
    cat /var/log/rkhunter.log | grep -i warning

    echo -e "${SUCCESS} \u2714 Installation et configuration de rkhunter terminée.${NC}"

  fi
  if [[ ${choices[4]} ]]; then
    #Installation et configuration de chkrootkit.
    echo -e "${INFO}Installation de chkrootkit${NC}"
    apt install -q -y chkrootkit

    if [ -z "$adminmail" ]; then
      read -p "Veuillez entrer votre adresse courriel pour recevoir les alertes : " adminmail
      read -p "Votre domaine d'émission smtp :" domainesmtp
    fi

    echo -e "${INFO} Mise en place d'un scan quotidien ${NC}"
    cat <<EOF > /root/chkrootkit_daily.sh
#!/bin/bash
LOGFILE="/var/log/chkrootkit/chkrootkit-\$(date +'%Y-%m-%d').log";
EMAIL_MSG="Rapport chkrootkit pour serveur ${HOSTNAME}.";
EMAIL_FROM="chkrootkit-daily@${domainesmtp}";
EMAIL_TO="${adminmail}";

chkrootkit | tee \$LOGFILE
cat \$LOGFILE | grep -i warning | mail -a "\$LOGFILE" -s "rootkit Found" -a "From: \$EMAIL_FROM" "\$EMAIL_TO"

exit 0
EOF
    chmod 0755 /root/chkrootkit_daily.sh
    ln /root/chkrootkit_daily.sh /etc/cron.daily/chkrootkit_daily

    echo -e "${SUCCESS} \u2714 Installation et configuration de chkrootkit terminée.${NC}"

  fi
  if [[ ${choices[5]} ]]; then
    #Installation et configuration de suricata.
    echo -e "${INFO}Installation de suricata${NC}"
    echo
    apt install -q -y suricata
    modprobe nfnetlink_queue
    echo -e "${WARNING} Pour activer IPS sur une VM : Options du FW de la vm : ips:1 et ips_queues: 0 ${NC}"
    echo -e "${WARNING} ou bien /etc/pve/firewall/<VMID>.fw
[OPTIONS]
ips: 1
ips_queues: 0
${NC}"
    echo "nfnetlink_queue" >> /etc/modules
    NEEDREBOOT=1
    echo -e "${SUCCESS} \u2714 Installation et configuration de suricata terminée.${NC}"
  fi
  if [[ ${choices[6]} ]]; then
    echo -e "${INFO} Installation de la miniProbe PRTG ${NC}"
    apt install -q -y netcat python-setuptools
    cd /opt
    git clone https://github.com/atd16/PythonMiniProbe.git
    cd PythonMiniProbe
    ./install.sh
    echo -e "${SUCCESS} \u2714 Capteur PRTG installé ${NC}"
    echo "cd /opt/PythonMiniProbe/miniprobe && python setup.py configure"
  fi
  if [[ ${choices[7]} ]]; then
    echo -e "${INFO} Installation de ClamAV ${NC}"
    apt install -q -y clamav clamav-daemon
    echo -e "${INFO} Mise à jour de la base de donnée virale ${NC}"
    freshclam
    echo -e "${INFO} Test de détection d'un virus ${NC}"
    wget -P . http://www.eicar.org/download/eicar.com
    clamscan --infected --remove --recursive .

    if [ -z "$adminmail" ]; then
      read -p "Veuillez entrer votre adresse courriel pour recevoir les alertes : " adminmail
      read -p "Votre domaine d'émission smtp :" domainesmtp
    fi

    echo -e "${INFO} Mise en place d'un scan quotidien ${NC}"
    cat <<EOF > /root/clamscan_daily.sh
#!/bin/bash
LOGFILE="/var/log/clamav/clamav-\$(date +'%Y-%m-%d').log";
EMAIL_MSG="Rapport Clamav pour serveur ${HOSTNAME}.";
EMAIL_FROM="clamav-daily@${domainesmtp}";
EMAIL_TO="${adminmail}";
DIRTOSCAN="/var/www /var/vmail";

for S in \${DIRTOSCAN}; do
 DIRSIZE=\$(du -sh "\$S" 2>/dev/null | cut -f1);

 echo "Starting a daily scan of "\$S" directory.
 Amount of data to be scanned is "\$DIRSIZE".";

 clamscan -ri "\$S" >> "\$LOGFILE";

 # get the value of "Infected lines"
 MALWARE=\$(tail "\$LOGFILE"|grep Infected|cut -d" " -f3);

 # if the value is not equal to zero, send an email with the log file attached
 if [ "\$MALWARE" -ne "0" ];then
 # using heirloom-mailx below
 echo "\$EMAIL_MSG"|mail -a "\$LOGFILE" -s "Malware Found" -a "From: \$EMAIL_FROM" "\$EMAIL_TO";
 fi
done

exit 0
EOF
    chmod 0755 /root/clamscan_daily.sh
    ln /root/clamscan_daily.sh /etc/cron.daily/clamscan_daily
    echo -e "${SUCCESS} \u2714 Scan quotidien ClamAV installé ${NC}"
  fi
}

#Clear screen for menu
clear
echo -e "${SUCCESS}
                                                    ,                          
                                                     /.                        
                                                      ,,                       
                                                       *,                      
                                                        ,.                     
                                                         *                     
                                                         *                     
                                                         *.                    
                     .,**,..   ...,*,.                   *.                    
                 .*,             ..    ,*,               (.     ...            
              .** ,...    .,,,,,,*#(,.....,/,           ,/,*//////////,        
             *, .,#@&@,  .&@@&&@&&@@@@@@@@@%,       .,*///////////////*.     
           .,    #@@@@&.  .../@@@,..(@@#,.,(@@@/.   .,*///////////////////*    
          ,.    *@@#,@@#,    /@@@,  (@@/.   ,@@. .*/////*   */*. ****/////.  
         ,.    (&@@*,%@@&.   ,,&@,  (@@/.   *@@&*,.,*//.      *.  .///,/////*  
        .,    .@@@@@@@@@@/    ,#&,  /%(.   *&@@/. *///*,,,.  .*   ,,*,*//////  
       .,     (@@%    ,/(#.   %@@///&@@@@@@@@&*  (%*//////,   ,   .//*.*/////. 
       ,,         .,.                         *%#.,,*/////,   *.  ,//*  .*//*  
       ,,            ..                   .*#**,,,.*//////,   //*      ,*///.  
       ,,      .......   ....      .,,****,*,,,,,,,**/////***,*///*,,**////,   
       ,* ,,.            .,,            .*.*,,,,,,.* ,///////////////////*     
      .*/.   ..,,,,..        ,.       *. *,,,,,,,,,.   ,*/////////////*.       
    .*   ***.          ...     ,,  .*..**,*,,,,,,.*       .,,*****,            
   .,  .,/,   ,**,*,,.           .,, ,*.*,*,,,,,,*                             
  .,  *,  ./*           .      .*. .*.,,*,*,,,,,,                              
  ,  *.  ,*.*.**,   ..       .*   *,,,,,*,*,,,/.                               
 ,  ,,  ,*  /,*            ,,  .*,,,*,,,*,,,*,                                 
 ,  *. .*. *,  ,*.       .*.  ,,,,,,,,,,,,*,                                   
 ,  *. */  *.     .*,  ,*   .*,,**,,..***.                                     
 ,  *, ,/  ,*        *,.,**/******,,.                                          
 .. .*  ,,   ,     *.    *.                  ......                            
  *  *,  *,      ,,    ,*  *((((((* ,,,,,,,.//**/(/.                           
   ,  ,*.     .*,    .,    *((((((* *,,,*,,.//**/(/.                           
    ,.      .*     .*      *((((((* *,,,*,,.//**/(/,                           
      ,.  .*      *.       .******.         ... ..                             
       ..,.                                                                    
                      \033[1mAGENCE TECHNIQUE
		      DE LA CHARENTE\033[0m${NC}"
sleep 2
clear

#Menu function
function MENU {
  echo -e "${INFO}#################################################################################################
#                                                                                               #
#                                        PROXMOX VE 5                                           #
#                                        Post Install                                           #
#                                                                                               #
#   PROXMOX    : - client ntp                     SECURISATION : - SSH                          #
#                - proxy local                                   - Lynis                        #
#                - mails                                         - rkhunter                     #
#                - pigz (gzip)                                   - chkrootkit                   #
#                - postfix                                       - suricata                     #
#                - mail a chaque connexion ssh                                                  #
#                                                                                               #
#   SUPERVISON : - PRTG                           ANTIVIRUS    : - ClamAV                       #
#                                                                                               #
#################################################################################################
#                                                                                               #
#   ATD16 : 2019/02/07        Auteur: Yann Bogdanovic <ybogdanovic@atd16.fr>           v1.0.1   #
#                                                                                               #
#################################################################################################${NC}"

  for NUM in ${!options[@]}; do
    if [[ "${choices[NUM]:- }" ]]; then
      if [[ "${choices[NUM]}" == "+" ]]; then
        echo -e "${SUCCESS}[""${choices[NUM]:- }""]" $(( NUM+1 ))") ${options[NUM]}${NC}"
      else
        echo -e "[""${choices[NUM]:- }""]" $(( NUM+1 ))") ${options[NUM]}"
      fi
    fi
  done
  echo -e "${DANGER}$ERROR${NC}"
#  echo -e "${INFO}Sélectionnez les actions à faire (1 ou plus) puis ENTREE quand votre choix est fait): ${NC}"
}

#Menu loop
while MENU && read -e -p "$(echo -e $WARNING"Sélectionnez les actions à faire (1 ou plus) puis ENTREE (q ou Q pour quitter): "$NC)" -n1 SELECTION && [[ -n "$SELECTION" ]]; do
  clear
  if [[ "$SELECTION" == *[[:digit:]]* && $SELECTION -ge 1 && $SELECTION -le ${#options[@]} ]]; then
    (( SELECTION-- ))
    if [[ "${choices[SELECTION]}" == "+" ]]; then
      choices[SELECTION]=""
    else
      choices[SELECTION]="+"
    fi
      ERROR=" "
  else
    if [[ "$SELECTION" == "q" || "$SELECTION" == "Q" ]]; then
      echo "A bientôt"
      ERROR=" "
      exit 0
    fi
    ERROR="Option invalide: $SELECTION"
  fi
done


ACTIONS

if [ -z "$NEEDREBOOT" ]; then
  read -r -p "Terminé, voulez-vous redémarrer le serveur maintenant ? <Y/n> " prompt
  if [[ $prompt == "y" || $prompt == "Y" || $prompt == "yes" || $prompt == "Yes" ]]
  then
    echo "le serveur va redémarrer"
    shutdown -r now
  else
    echo -e "${WARNING}le serveur doit être redémarré${NC}"
  fi
fi
exit 0
