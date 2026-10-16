
$0889d3d9-0cd6-402a-80ec-83d1d17f0d20©
$1595f1d8-a772-8024-afc5-18102be9e2ffgate-servers *Õ»ÅÖ×åæê2
0cf1ab12e505linux"amd64:

assessmentJY
shadow-permissionsA/etc/shadow is a regular file owned by 0:42 with permissions 0640Jt
passwd-private`/etc/passwd is a regular file owned by 0:0 with permissions 0644: its permissions go beyond 0600J’
	root-home‚the agent's service hides /root from it: a drop-in for seagull-agent.service that sets ProtectHome=read-only lets the agent see itJ.
hosts-equiv/etc/hosts.equiv is not thereJÔ
private-fileÁthe agent's account cannot reach /etc/seagull-native-assess/secret, as /etc/seagull-native-assess cannot be searched: a drop-in for seagull-agent.service that grants CAP_DAC_READ_SEARCH lets itJ2
	superuser#no account but root holds user id 0JU
assess-group-empty=group seagull-native-assess has members seagull-native-memberJ*
aslr kernel.randomize_va_space is "2"JS
no-such-parameter<the kernel has no parameter kernel.seagull_no_such_parameterJº
cramfs­cramfs is not loaded; /etc/modprobe.d/seagull-native-assess.conf line 1 has modprobe run "/bin/false" for it; /etc/modprobe.d/seagull-native-assess.conf line 2 blacklists itJT
usb-storageCno install line of the modprobe configuration keeps usb-storage outJF

ssh-server6openssh-server 1:9.6p1-3ubuntu13.20 amd64 is installedJ%
telnetdtelnetd is not installedJ;
journald-systemd-journald.service is static and activeJ-
rsync"the host has no unit rsync.serviceJ†
password-authsPasswordAuthentication is "yes" at /etc/ssh/sshd_config.d/10-seagull-native-assess.conf line 1, which is none of noJÀ

root-login¯PermitRootLogin is "yes" in a Match block for User seagull-native-member at /etc/ssh/sshd_config.d/10-seagull-native-assess.conf line 3, which is none of no, prohibit-passwordJ|
allow-usersksshd gathers AllowUsers from every line that names it, and the agent judges a directive sshd takes from oneJR
pass-max-days?PASS_MAX_DAYS is "99999" at /etc/login.defs line 165, above 365J5
umask*UMASK is "022" at /etc/login.defs line 151Jw
from-tomorrowdthe agent does not read the check: it carries a test, or a value in one, newer than this agent reads