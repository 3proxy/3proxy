#!/bin/bash
# 3proxy build and install script for Debian Linux 
# Release 2.0 at 29.12.2016
# (с) Evgeniy Solovyev 
# mail-to: eugen-soloviov@yandex.ru

ScriptPath=""
Src3proxyDirPath=""
ScriptName=""
ScriptFullName=""
SourceRoot=""

ResourcesData=""


ProxyVersion=""
LasestProxyVersion=""
LasestProxyVersionLink=""
UseSudo=0
PacketFiles=""
NeedSourceUpdate=0


main()
{
	local msgNewVersion
	local msgInsertYorN
	
	VarsInit
	LoadResources
	CheckRunConditions
	
	if [ $UseSudo == 1 ]
	then
		sudo bash "${0}"
		exit $?
	fi
	
	CheckLocation
	GetLasestVersionInfo
	
	SourceDownloadOrUpdate
	
	cd "${SourceRoot}"
	
	Build3Proxy
	BinInstall
	ManInstall
	CreateLogDir
	CopyConfig
	SetInit
	Pack3proxyFiles
}

VarsInit()
{
	cd `dirname $0`
	ScriptPath="${PWD}"
	ScriptName=`basename $0`
	ScriptFullName="${ScriptPath}/${ScriptName}"
}

CheckLocation()
{
	Src3proxyDirPath="${ScriptPath}"
	
	if echo ${ScriptPath} | grep -e "/scripts$"
	then
		if [ -e "../src/version.h" ]
		then
			ProxyVersion=`cat "../src/version.h" | awk '/VERSION/ { gsub("\"", "\n"); print; exit }' | grep "3proxy"`
			cd ../
			SourceRoot="${PWD}"
			cd ../
			Src3proxyDirPath="${PWD}"
			cd "${ScriptPath}"
		fi
	fi
}

GetLasestVersionInfo()
{
	local Githublink
	local msg
	
	Githublink=`wget https://github.com/z3APA3A/3proxy/releases/latest -O /dev/stdout |
	awk '/<a.+href=.+\.tar\.gz/ { gsub("\"", "\n"); print; exit }' |
	grep -e ".tar.gz"`
	if [ $? != 0 ]
	then
		msg=`GetResource "msgInternetConnectionError"`
		echo -e "${msg}"
		exit 255
	fi
	
	LasestProxyVersionLink="https://github.com${Githublink}"

	LasestProxyVersion=`basename "${Githublink}" | awk 'gsub(".tar.gz", "") { print "3proxy-" $0 }'`
}

CheckRunConditions()
{
	local UserName
	local answer
	local msg
	local msgContinueWork
	local msgInsertYorN
	
	UserName=`whoami`
	
	if [  $UID != 0 ]
	then
		if [ `CheckPacketInstall "sudo"` == 0 ]
		then
			msg=`GetResource "msgSudoNotInstalled"`
			echo -e "${msg}"
			exit 255
		fi
		
		UseSudo=1
		
		if [ -z `cat /etc/group | grep -e "^sudo" | grep "${UserName}"`  ]
		then
			msg=`GetResource "msgUserNotMemberOfSudoGroup"`
			echo -e "${msg}"
			exit 255
		fi
		
		if [ `env | grep -e ^http_proxy` != "" ]
		then
			msg=`GetResource "msgSystemUseProxy"`
			echo -e "${msg}"
			
			msgContinueWork=`GetResource "msgDoYouWishContinue"`
			msgInsertYorN=`GetResource "msgPleaseInsertYorN"`
			
			while true; do
				read -s -n1 -p "${msgContinueWork}" answer
				case $answer in
					[Yy]* ) echo -ne "\n";break;;
					[Nn]* ) echo -ne "\n"; sleep 0; exit 0;;
					* ) echo -e "${msgInsertYorN}";;
				esac
			done
		
		fi
	fi
	
}

DonwnloadSource()
{
	if [ ! -e "${Src3proxyDirPath}/${LasestProxyVersion}.tar.gz" ] 
	then
		wget "${LasestProxyVersionLink}" -O "${Src3proxyDirPath}/${LasestProxyVersion}.tar.gz"
	fi
	
	ProxyVersion="${LasestProxyVersion}"
}

UnpackSource()
{
	if [ ! -d "${Src3proxyDirPath}/${LasestProxyVersion}" ]
	then
		tar -xvf "${Src3proxyDirPath}/${LasestProxyVersion}.tar.gz" -C "${Src3proxyDirPath}"
	fi
	
	SourceRoot="${Src3proxyDirPath}/${LasestProxyVersion}"
}

SourceDownloadOrUpdate()
{
	if [ -z "${ProxyVersion}" ]
	then
		NeedSourceUpdate=1
	else
		if [ "${ProxyVersion}" != "${LasestProxyVersion}" ]
		then
			msgNewVersion=`GetResource "msgNewVersion"`
			msgInsertYorN=`GetResource "msgPleaseInsertYorN"`
			
			echo -ne "\a"
			
			while true; do
				read -s -n1 -p "${msgNewVersion}" answer
				case $answer in
					[Yy]* ) echo -ne "\n"; NeedSourceUpdate=1; sleep 0; break;;
					[Nn]* ) echo -ne "\n"; NeedSourceUpdate=0; sleep 0; break;;
					* ) echo -e "${msgInsertYorN}";;
				esac
			done
		fi
	fi
	
	if [ $NeedSourceUpdate == 1 ]
	then
		DonwnloadSource
		UnpackSource
	fi
}

Build3Proxy()
{
	local msg
	
	if [ `CheckPacketInstall "build-essential"` == 0 ]
	then
		apt-get -y install build-essential
	fi
	
	if [ `CheckPacketInstall "build-essential"` == 0 ]
	then
		msg=`GetResource "msgBuildEssentialNotInstalled"`
		echo -e "${msg}"
		
		exit 255
	fi
	
	make -f Makefile.Linux
}


BinInstall()
{
	local binlist
	local liblist
	
	if [! -d bin]
	then
		mkdir bin
	fi
	
	cd bin
	
	binlist=`ls -l --time-style="+%d.%m.%Y %H:%m" | awk '$1 ~ /x$/ && $1 ~ /^[^d]/ && $8 !~ /\.so$/ { print $8 }'`
	
	for file in $binlist
	do
		cp -vf "${file}" /usr/bin
		PacketFiles=`echo -e "${PacketFiles}\n/usr/bin/${file}"`
	done
	
	liblist=`ls -l --time-style="+%d.%m.%Y %H:%m" | awk '$1 ~ /x$/ && $1 ~ /^[^d]/ && $8 ~ /\.so$/ { print $8 }'`

	for file in $liblist
	do
		cp -vf "${file}" /usr/lib
		PacketFiles=`echo -e "${PacketFiles}\n/usr/lib/${file}"`
	done

	cd ..
}

ManInstall()
{
	local man3list
	local man8list
	
	cd man
	
	man3list=`ls -l --time-style="+%d.%m.%Y %H:%m" | awk '$8 ~ /\.3$/ { print $8 }'`
	gzip -vfk $man3list
	
	man3list=`echo "${man3list}" | awk '{ print $1 ".gz" }'`
	
	for file in $man3list
	do
		mv -vf "${file}" /usr/share/man/man3
		PacketFiles="${PacketFiles}\n/usr/share/man/man3/${file}" 
	done
	
	man8list=`ls -l --time-style="+%d.%m.%Y %H:%m" | awk '$8 ~ /\.8$/ { print $8 }'`
	
	gzip -vfk $man8list
	
	man8list=`echo "${man8list}" | awk '{ print $1 ".gz" }'`
	
	for file in $man8list
	do
		mv -vf "${file}" /usr/share/man/man8
		PacketFiles=`echo -e "${PacketFiles}\n/usr/share/man/man8/${file}"`
	done
	
	cd ..
}


CreateLogDir()
{
	local LogDir
	LogDir="/var/log/3proxy"
	
	if [ ! -d  "${LogDir}" ]
	then
		mkdir "${LogDir}"
	fi
	
	chown nobody:nogroup "${LogDir}"
	chmod 775 "${LogDir}"
	PacketFiles="${PacketFiles}\n${LogDir}" 
}


CopyConfig()
{
	local ConfigDir
	ConfigDir="/etc/3proxy"
	
	if [ ! -d  "${ConfigDir}" ]
	then
		mkdir "${ConfigDir}"
	fi
	
	LoadGlobalResource "ConfigFile" > "${ConfigDir}/3proxy.cfg"

	PacketFiles=`echo -e "${PacketFiles}\n${ConfigDir}/3proxy.cfg"`
}


SetInit()
{
	LoadGlobalResource "InitScript" > "/etc/init.d/3proxy"
	chown root:root "/etc/init.d/3proxy"
	chmod 755 "/etc/init.d/3proxy"
	
	PacketFiles=`echo -e "${PacketFiles}\n/etc/init.d/3proxy"`
	update-rc.d 3proxy defaults
}

Pack3proxyFiles()
{
	local CPU_Arc
	CPU_Arc=`uname -m`
	cd ../
	tar -czPpvf "${ProxyVersion}-${CPU_Arc}.tar.gz" $PacketFiles
}

LoadResources()
{
	local StartRow
	local EndRow
	local LngLabel
	local msgResourceErr="\aError! Script could not find resources!"
	
	if env | grep -q 'LANG=ru_RU.UTF-8' 
	then
		LngLabel="RU"
#LngLabel="EN"
	else
		LngLabel="EN"
	fi
	
	StartRow=`cat "${ScriptFullName}" | awk "/^#Resources_${LngLabel}/ { print NR; exit}"`
	
	if [ -z "${StartRow}" ]
	then
		echo -e "${msgResourceErr}"
		exit 255
	fi
	
	EndRow=`cat "${ScriptFullName}" | awk "NR > ${StartRow} && /^#Resources_${LngLabel}_end/ { print NR; exit}"`
	
	if [ -z "${EndRow}" ]
	then
		echo -e "${msgResourceErr}"
		exit 255
	fi
	
	ResourcesData=`cat "${ScriptFullName}" | awk -v StartRow="${StartRow}" -v EndRow="${EndRow}" 'NR > StartRow && NR < EndRow { print $0 }'`
}


# $1 - Name of Resource
GetResource()
{
	local StartRow
	local EndRow
	local msgResourceErr="\aError! Script could not find resource \"${1}\"!"
	
	StartRow=`echo "${ResourcesData}" | awk "/^#Resource=${1}/ { print NR; exit}"`
	
	if [ -z "${StartRow}" ]
	then
		echo -e "${msgResourceErr}" > /dev/stderr
		exit 255
	fi
	
	EndRow=`echo "${ResourcesData}" | awk "NR > ${StartRow} && /^#endResource=${1}/ { print NR; exit}"`
	
	if [ -z "${EndRow}" ]
	then
		echo -e "${msgResourceErr}" > /dev/stderr
		exit 255
	fi
	
	echo "${ResourcesData}" | awk -v StartRow="${StartRow}" -v EndRow="${EndRow}" 'NR > StartRow && NR < EndRow { print $0 }'
}


# $1 - Name of Resource
LoadGlobalResource()
{
	local StartRow
	local EndRow
	local LngLabel
	local msgResourceErr="\aError! Script could not find resource \"${1}\"!"
	
	
	StartRow=`cat "${ScriptFullName}" | awk "/^#Resource=${1}/ { print NR; exit}"`
	
	if [ -z "${StartRow}" ]
	then
		echo -e "${msgResourceErr}" > /dev/stderr
		exit 255
	fi
	
	EndRow=`cat "${ScriptFullName}" | awk "NR > ${StartRow} && /^#endResource=${1}/ { print NR; exit}"`
	
	if [ -z "${EndRow}" ]
	then
		echo -e "${msgResourceErr}" > /dev/stderr
		exit 255
	fi
	
	cat "${ScriptFullName}" | awk -v StartRow="${StartRow}" -v EndRow="${EndRow}" 'NR > StartRow && NR < EndRow { print $0 }'
}


CheckPacketInstall()
{
	if [ `dpkg -l ${1} 2>&1 | wc -l` -le 1 ]  
	then
		echo 0
		return
	fi
	if [ `dpkg -l ${1} | grep -e ^un | wc -l` == 1 ]
	then
		echo 0
		return
	fi
	
	echo 1
}

main
exit 0

#Resources_EN

#Resource=msgSudoNotInstalled
\aThe script is running under the account a non-privileged user.
"Sudo" package is not installed in the system.
The script can not continue, as the execution of operations,
requiring rights "root" - is not possible!
Please run the script under the account "root",
or install and configure "sudo" package!
#endResource=msgSudoNotInstalled

#Resource=msgUserNotMemberOfSudoGroup
\aThe script is running under account a non-privileged user.
The account of the current user is not included in the "sudo" group!
The script can not continue, as the execution of operations,
requiring rights "root" - is not possible!
Please run the script under the account "root",
or configure "sudo" package!
#endResource=msgUserNotMemberOfSudoGroup

#Resource=msgSystemUseProxy
\aAttention! The operating system uses proxy-server.
For correctly work of package manager "apt" 
in the file "/etc/sudoers" should be present line:
Defaults env_keep = "http_proxy https_proxy"
#endResource=msgSystemUseProxy

#Resource=msgDoYouWishContinue
Do you wish to the script continued executing? (y/n):
#endResource=msgDoYouWishContinue

#Resource=msgPleaseInsertYorN
\a\nPlease insert "y" or "n"!
#endResource=msgPleaseInsertYorN

#Resource=msgInternetConnectionError
\aError downloading "https://github.com/z3APA3A/3proxy/releases/latest"!
Please check the settings of the Internet connection.
#endResource=msgInternetConnectionError

#Resource=msgNewVersion
The new version of "3proxy" detected, do you want download it?
#endResource=msgNewVersion

#Resource=msgBuildEssentialNotInstalled
\aPackage "build-essential" was not installed.
The installation can not be continued!
#endResource=msgBuildEssentialNotInstalled

#Resources_EN_end

#Resources_RU

#Resource=msgSudoNotInstalled
\aСкрипт запущен под учётной записью обычного пользователя.
В системе не установлен пакет "sudo".
Скрипт не может продолжить работу, так как выполнение операций,
требующих прав "root" - не представляется возможным!
Пожалуйста, запустите скрипт под учётной записью "root", 
либо установите и настройте пакет "sudo"!
#endResource=msgSudoNotInstalled

#Resource=msgUserNotMemberOfSudoGroup
\aСкрипт запущен под учётной записью обычного пользователя.
Учётная запись текущего пользователя не включена в группу "sudo"!
Скрипт не может продолжить работу, так как выполнение операций,
требующих прав "root" - не представляется возможным!
Пожалуйста, запустите скрипт под учётной записью "root", 
либо настройте пакет "sudo"!
#endResource=msgUserNotMemberOfSudoGroup

#Resource=msgSystemUseProxy
\aВнимание! В системе используется прокси-сервер.
Чтобы менеджер пакетов "apt" работал корректно,
в файле "/etc/sudoers" должна присутствовать строка:
Defaults env_keep = "http_proxy https_proxy"
#endResource=msgSystemUseProxy

#Resource=msgDoYouWishContinue
Хотите чтобы скрипт дальше продолжил работу? (y/n):
#endResource=msgDoYouWishContinue

#Resource=msgPleaseInsertYorN
\a\nПожалуйста введите "y" или "n"!
#endResource=msgPleaseInsertYorN

#Resource=msgInternetConnectionError
\aОшибка закачки "https://github.com/z3APA3A/3proxy/releases/latest"!
Пожалуйста, проверьте настройки интернет соединения.
#endResource=msgInternetConnectionError

#Resource=msgNewVersion
Обнаружена новая версия "3proxy", скачать её (y/n)?
#endResource=msgNewVersion

#Resource=msgBuildEssentialNotInstalled
\aПакет "build-essential" не был установлен.
Дальнейшая установка не может быть продолжена!
#endResource=msgBuildEssentialNotInstalled

#Resources_RU_end


#Resource=ConfigFile
noconfig
# If in this file have line "noconfig", then 3proxy not to be runned!
# For usung this configuration file 3proxy you must to delete 
# or comment out the line with "noconfig".

daemon
# Parameter "daemon" - means run 3proxy as daemon


pidfile /tmp/3proxy.pid
# PID file location 
# This parameter must have the same value as 
# the variable "PidFile" in  the script "/etc/init.d/3proxy"


# Configuration file location
config /etc/3proxy/3proxy.cfg


internal 127.0.0.1
# Internal is address of interface proxy will listen for incoming requests
# 127.0.0.1 means only localhost will be able to use this proxy. This is
# address you should specify for clients as proxy IP.
# You MAY use 0.0.0.0 but you shouldn't, because it's a chance for you to
# have open proxy in your network in this case.

external 192.168.0.1
# External is address 3proxy uses for outgoing connections. 0.0.0.0 means any
# interface. Using 0.0.0.0 is not good because it allows to connect to 127.0.0.1


# DNS IP addresses
nserver 8.8.8.8
nserver 8.8.4.4


# DNS cache size
nscache 65536

# Timeouts settings
timeouts 1 5 30 60 180 1800 15 60


# log file location
log /var/log/3proxy/3proxy.log D

# log file format
logformat "L%C - %U [%d-%o-%Y %H:%M:%S %z] ""%T"" %E %I %O %N/%R:%r"

archiver gz /usr/bin/gzip %F
# If archiver specified log file will be compressed after closing.
# you should specify extension, path to archiver and command line, %A will be
# substituted with archive file name, %f - with original file name.
# Original file will not be removed, so archiver should care about it.

rotate 30
# We will keep last 30 log files

proxy -p3128
# Run http/https proxy on port 3128

auth none
# No authentication is requires

setgid 65534
setuid 65534
# Run 3proxy under account "nobody" with group "nobody"
#endResource=ConfigFile


#Resource=InitScript
#!/bin/sh
#
# 3proxy daemon control script
#
### BEGIN INIT INFO
# Provides:          3proxy
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $network $remote_fs $syslog
# Should-Start:      $named
# Should-Stop:       $named
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: 3proxy HTTP Proxy
### END INIT INFO


ScriptName="3proxy"
ScriptFullName="/etc/init.d/3proxy"

ConfigFile="/etc/3proxy/3proxy.cfg"
LogDir="/var/log/3proxy"
PidFile="/tmp/3proxy.pid"

ResourcesData=""

main()
{
	LoadResources
	
	if [ ! -d "${LogDir}" ]
	then
		mkdir -p "${LogDir}";
	fi
	
	case "$1" in
		start)		Start ;;
		stop)		Stop ;;
		restart)	Stop; Start ;;
		status)		Status ;;
		*)			ShowHelp;;
	esac
}

Start()
{
	local msg
	local ProxyPID
	
	if [ ! -f "${ConfigFile}" ]
	then
		msg=`GetResource "msgConfigFileNotFound"`
		printf "${msg}" "${ConfigFile}"
		return
	fi
	
	if cat "${ConfigFile}" | grep -qe "^noconfig"
	then
		msg=`GetResource "msgNoconfigDetected"`
		printf "${msg}" "${ConfigFile}"
		return
	fi
	
	ProxyPID=`Get3proxyPID`
	
	if [ ! -z "${ProxyPID}" ]
	then
		msg=`GetResource "msg3proxyAlreadyRunning"`
		printf "${msg}" "${ProxyPID}"
		return
	fi
	
	3proxy "${ConfigFile}"
	sleep 1
	
	ProxyPID=`Get3proxyPID`
	
	if [ ! -f "${PidFile}" ] 
	then
		msg=`GetResource "msg3proxyStartProblems"`
		printf "${msg}"
		return
	fi
	
	if [ `cat "${PidFile}"` != "${ProxyPID}" ]
	then
		msg=`GetResource "msg3proxyStartProblems"`
		printf "${msg}"
		return
	fi
	
	msg=`GetResource "msg3proxyStartedSuccessfully"`
	printf "${msg}" `date +%d-%m-%Y" "%H:%M:%S` "${ProxyPID}"

}

Stop()
{
	local msg
	local ProxyPID
	
	ProxyPID=`Get3proxyPID`
	
	if [ -f "${PidFile}" ] 
	then
		if [ `cat "${PidFile}"` = "${ProxyPID}" ]
		then
			kill -9 "${ProxyPID}"
			rm -f "${PidFile}"
			
			msg=`GetResource "msg3proxyStoppedSuccessfully"`
			printf "${msg}" `date +%d-%m-%Y" "%H:%M:%S`
			
			return
		fi
	fi
	
	if [ -z "${ProxyPID}" ]
	then
		msg=`GetResource "msg3proxyProxyNotDetected"`
		printf "${msg}"
		
		return
	fi
	
	pkill -o 3proxy
	
	msg=`GetResource "msg3proxyStoppedByKillall"`
	printf "${msg}" `date +%d-%m-%Y" "%H:%M:%S` "${PidFile}"
	
}

Status()
{
	local msg
	local ProxyPID
	
	if [ -f "${PidFile}" ] 
	then
		msg=`GetResource "msgPidFileExists"`
		printf "${msg}" "${PidFile}" `cat "${PidFile}"`
	else
		msg=`GetResource "msgPidFileNotExists"`
		printf "${msg}" "${PidFile}"
	fi
	
	ProxyPID=`Get3proxyPID`
	
	if [ ! -z  "${ProxyPID}" ]
	then
		msg=`GetResource "msg3proxyProcessDetected"`
		printf "${msg}"
		ps -ef | awk '$8 ~ /^3proxy/ { print "User: " $1 "\tPID: " $2 }'
	else
		msg=`GetResource "msg3proxyProcessNotDetected"`
		printf "${msg}"
	fi
}

ShowHelp()
{
	local msg
	
	msg=`GetResource "msg3proxyHelp"`
	printf "${msg}" "${ScriptFullName}" "${ScriptName}"
}

Get3proxyPID()
{
	ps -ef | awk '$8 ~ /^3proxy/ { print $2; exit }'
}

LoadResources()
{
	local StartRow
	local EndRow
	local LngLabel
	local msgResourceErr="\aError! Script could not find resources!"
	
	if env | grep -q 'LANG=ru_RU.UTF-8' 
	then
		LngLabel="RU"
	else
		LngLabel="EN"
	fi
	
	StartRow=`cat "${ScriptFullName}" | awk "/^#Resources_${LngLabel}/ { print NR; exit}"`
	
	if [ -z "${StartRow}" ]
	then
		echo -e "${msgResourceErr}"
		exit 255
	fi
	
	EndRow=`cat "${ScriptFullName}" | awk "NR > ${StartRow} && /^#Resources_${LngLabel}_end/ { print NR; exit}"`
	
	if [ -z "${EndRow}" ]
	then
		echo -e "${msgResourceErr}"
		exit 255
	fi
	
	ResourcesData=`cat "${ScriptFullName}" | awk -v StartRow="${StartRow}" -v EndRow="${EndRow}" 'NR > StartRow && NR < EndRow { print $0 }'`
}

# $1 - Name of Resource
GetResource()
{
	local StartRow
	local EndRow
	local msgResourceErr="\aError! Script could not find resource \"${1}\"!"
	
	StartRow=`echo "${ResourcesData}" | awk "/^#Resource=${1}/ { print NR; exit}"`
	
	if [ -z "${StartRow}" ]
	then
		echo -e "${msgResourceErr}" > /dev/stderr
		exit 255
	fi
	
	EndRow=`echo "${ResourcesData}" | awk "NR > ${StartRow} && /^#endResource=${1}/ { print NR; exit}"`
	
	if [ -z "${EndRow}" ]
	then
		echo -e "${msgResourceErr}" > /dev/stderr
		exit 255
	fi
	
	echo "${ResourcesData}" | awk -v StartRow="${StartRow}" -v EndRow="${EndRow}" 'NR > StartRow && NR < EndRow { print $0 }'
}


main $@
exit 0;

#Resources_EN

#Resource=msg3proxyHelp
Usage:
\t%s {start|stop|restart}
or
\tservice %s {start|stop|restart|status}\\n
#endResource=msg3proxyHelp

#Resource=msgConfigFileNotFound
\a3proxy configuration file - "%s" is not found!\\n
#endResource=msgConfigFileNotFound

#Resource=msgNoconfigDetected
Parameter "noconfig" found in 3proxy configuration file -
"% s" !
To run 3proxy this parameter should be disabled.\\n
#endResource=msgNoconfigDetected

#Resource=msg3proxyAlreadyRunning
\a3proxy already running PID: %s\\n
#endResource=msg3proxyAlreadyRunning

#Resource=msg3proxyStartProblems
With the start of 3proxy, something is wrong! 
Use: service 3proxy status\\n
#endResource=msg3proxyStartProblems

#Resource=msg3proxyStartedSuccessfully
[ %s %s ] 3proxy started successfully! PID: %s\\n
#endResource=msg3proxyStartedSuccessfully

#Resource=msg3proxyStoppedSuccessfully
[ %s %s ] 3proxy stopped successfully!\\n
#endResource=msg3proxyStoppedSuccessfully

#Resource=msg3proxyProxyNotDetected
Process "3proxy" is not detected!\\n
#endResource=msg3proxyProxyNotDetected

#Resource=msg3proxyStoppedByKillall
[ %s %s ] Command "pkill -o 3proxy" was executed,
because process number was not stored in "%s",
but in fact 3proxy was runned!\\n
#endResource=msg3proxyStoppedByKillall

#Resource=msgPidFileExists
File "%s" exists. It contains the PID: %s\\n
#endResource=msgPidFileExists

#Resource=msgPidFileNotExists
File "%s" not found, that is, PID 3proxy was not stored!\\n
#endResource=msgPidFileNotExists

#Resource=msg3proxyProcessDetected
Process 3proxy detected:\\n
#endResource=msg3proxyProcessDetected

#Resource=msg3proxyProcessNotDetected
Processes of 3proxy is not found!\\n
#endResource=msg3proxyProcessNotDetected

#Resources_EN_end


#Resources_RU

#Resource=msg3proxyHelp
Используйте:
\t%s {start|stop|restart}
или
\tservice %s {start|stop|restart|status}\\n
#endResource=msg3proxyHelp

#Resource=msgConfigFileNotFound
\aФайл конфигурации 3proxy - "%s", не найден!\\n
#endResource=msgConfigFileNotFound

#Resource=msgNoconfigDetected
\aОбнаружен параметр "noconfig" в файле конфигурации 3proxy -
"%s" !
Для запуска 3proxy этот параметр нужно отключить.\\n
#endResource=msgNoconfigDetected

#Resource=msg3proxyAlreadyRunning
\a3proxy уже запущен PID: %s\\n
#endResource=msg3proxyAlreadyRunning

#Resource=msg3proxyStartProblems
\aСо стартом 3proxy, что-то не так!
Используйте: service 3proxy status\\n
#endResource=msg3proxyStartProblems

#Resource=msg3proxyStartedSuccessfully
[ %s %s ] 3proxy успешно стартовал! PID: %s\\n
#endResource=msg3proxyStartedSuccessfully

#Resource=msg3proxyStoppedSuccessfully
[ %s %s ] 3proxy успешно остановлен!\\n
#endResource=msg3proxyStoppedSuccessfully

#Resource=msg3proxyProxyNotDetected
Процесс "3proxy" не обнаружен!\\n
#endResource=msg3proxyProxyNotDetected

#Resource=msg3proxyStoppedByKillall
[ %s %s ] Выполнена команда "pkill -o 3proxy",
т.к. номер процесса не записан в "%s",
но по факту 3proxy рабатал!\\n
#endResource=msg3proxyStoppedByKillall

#Resource=msgPidFileExists
Файл "%s" есть. Он содержит PID: %s\\n
#endResource=msgPidFileExists

#Resource=msgPidFileNotExists
Файл "%s" не найден, т.е. PID 3proxy не был сохранён!\\n
#endResource=msgPidFileNotExists

#Resource=msg3proxyProcessDetected
Обнаружен процесс 3proxy:\\n
#endResource=msg3proxyProcessDetected

#Resource=msg3proxyProcessNotDetected
Процессов 3proxy не обнаружено!\\n
#endResource=msg3proxyProcessNotDetected

#Resources_RU_end
#endResource=InitScript
