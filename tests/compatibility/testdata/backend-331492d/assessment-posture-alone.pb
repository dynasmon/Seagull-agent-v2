
$c3689fde-f39b-8a60-bce8-9618edb03659gate-servers *±ú≈÷ÕÑ≠Ÿ2B
tenant-1792102345529634819web-01
0cf1ab12e505linux"amd64:

assessmentBF
…ü≈÷≈§‡»gateway-evidence$de6c8d4a-6f23-4833-bec8-562acc1bdef1JY
shadow-permissionsA/etc/shadow is a regular file owned by 0:42 with permissions 0640Jt
passwd-private`/etc/passwd is a regular file owned by 0:0 with permissions 0644: its permissions go beyond 0600Jí
	root-homeÇthe agent's service hides /root from it: a drop-in for seagull-agent.service that sets ProtectHome=read-only lets the agent see itJ.
hosts-equiv/etc/hosts.equiv is not thereJ‘
private-file¡the agent's account cannot reach /etc/seagull-native-assess/secret, as /etc/seagull-native-assess cannot be searched: a drop-in for seagull-agent.service that grants CAP_DAC_READ_SEARCH lets itJ2
	superuser#no account but root holds user id 0JU
assess-group-empty=group seagull-native-assess has members seagull-native-memberJ*
aslr kernel.randomize_va_space is "2"JS
no-such-parameter<the kernel has no parameter kernel.seagull_no_such_parameterJ∫
cramfs≠cramfs is not loaded; /etc/modprobe.d/seagull-native-assess.conf line 1 has modprobe run "/bin/false" for it; /etc/modprobe.d/seagull-native-assess.conf line 2 blacklists itJT
usb-storageCno install line of the modprobe configuration keeps usb-storage outJF

ssh-server6openssh-server 1:9.6p1-3ubuntu13.20 amd64 is installedJ%
telnetdtelnetd is not installedJ;
journald-systemd-journald.service is static and activeJ-
rsync"the host has no unit rsync.serviceJ‚
password-authŒa file the OpenSSH server reads cannot be read by the agent: /etc/ssh/sshd_config.d/20-seagull-native-private.conf: a drop-in for seagull-agent.service that grants CAP_DAC_READ_SEARCH lets the agent read itJﬂ

root-loginŒa file the OpenSSH server reads cannot be read by the agent: /etc/ssh/sshd_config.d/20-seagull-native-private.conf: a drop-in for seagull-agent.service that grants CAP_DAC_READ_SEARCH lets the agent read itJ|
allow-usersksshd gathers AllowUsers from every line that names it, and the agent judges a directive sshd takes from oneJR
pass-max-days?PASS_MAX_DAYS is "99999" at /etc/login.defs line 165, above 365J5
umask*UMASK is "022" at /etc/login.defs line 151Jw
from-tomorrowdthe agent does not read the check: it carries a test, or a value in one, newer than this agent reads