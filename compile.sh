#!/bin/bash

CUR_DIR=$(pwd)
ROOT_DIR=$(dirname $(readlink -f $0))
cd $ROOT_DIR

COLOR_CLEAR='\033[0m'
COLOR_RED='\033[0;31m'
COLOR_BLUE='\033[0;34m'
COLOR_GREEN='\033[0;32m'

checkReturnCode() {
	ret_=$?
	if [ $ret_ -ne 0 ]; then
		printf "${COLOR_RED}[hebang] fail,  retCode '$ret_' is invalid, in '$1' [file=${BASH_SOURCE[1]##*/} fun=${FUNCNAME[1]} line=${BASH_LINENO[0]}]${COLOR_CLEAR}\n" 
		exit 22
	fi
}

################################################## compile nginx
compileNginx() {
	rm -rf $INSTALL_DIR/sbin/*
	make
	checkReturnCode "make nginx"
	
	make install
	checkReturnCode "make install nginx"
	
	printf "${COLOR_BLUE}"
	ls -lh $INSTALL_DIR/sbin/nginx
	checkReturnCode
	printf "${COLOR_CLEAR}"

	printf "${COLOR_BLUE}************* done to build nginx *****************${COLOR_CLEAR}\n"
}

################################################## 获取命令行参数
for option   #option是内置变量，代表了当前脚本程序的参数集合(不含脚本程序名)
do
	case "$option" in
		*=*) value=`echo "$option" | sed -e 's/[-_a-zA-Z0-9]*=//'` ;;
		*) value="" ;;
	esac
	case "$option" in
		release=*) releaseOpt="$value" ;;
		compileOnly=*) compileOnlyOpt="$value" ;;
		buildDir=*) buildDirOpt="$value" ;;
	esac
done

printf "${COLOR_GREEN}releaseOpt=$releaseOpt compileOnlyOpt=$compileOnlyOpt buildDirOpt=$buildDirOpt${COLOR_CLEAR}\n"
printf "**************************************************\n"
sleep 3

################################################## 设置全局参数
if [ ! -z $releaseOpt ]; then
	DEBUG_FLAGS=
fi

if [ ! -z $buildDirOpt ]; then
	BUILD_DIR=$buildDirOpt
else
	BUILD_DIR=$ROOT_DIR/buildRtmp  #default build dir
fi

INSTALL_DIR=$BUILD_DIR/install
VSCODE_GDB_DIR=$ROOT_DIR
DEBUG_FLAGS=--with-debug

################################################## 增量编译
if [ ! -z $compileOnlyOpt ]; then
	cd $BUILD_DIR/nginx-1.14.0
	checkReturnCode

	compileNginx
	exit 0
fi

################################################## 第一次编译：创建编译目录，修改编译配置项，编译，修改nginx配置文件，修改vscode配置文件。
cd $ROOT_DIR

chmod a+x compile.sh
checkReturnCode

#创建编译目录
rm -rf $BUILD_DIR
checkReturnCode
mkdir -p $BUILD_DIR
checkReturnCode

#解压nginx压缩包
tar zxf ./doc/nginx-1.14.0.tar.gz -C $BUILD_DIR
checkReturnCode
cd $BUILD_DIR/nginx-1.14.0
checkReturnCode

#修改编译配置项
./configure --with-stream $DEBUG_FLAGS --without-http_rewrite_module --without-http_gzip_module --prefix=$INSTALL_DIR --add-module=$ROOT_DIR
checkReturnCode

#移除ipv6的支持。
chmod a+w ./objs/ngx_auto_config.h
sed 's/#define NGX_HAVE_INET6  1/#define NGX_HAVE_INET6  0/g' < ./objs/ngx_auto_config.h > .heb2
mv .heb2 ./objs/ngx_auto_config.h

#编译安装nginx
compileNginx

#修改nginx配置文件
rm -rf $INSTALL_DIR/conf/nginx.conf
cp $ROOT_DIR/doc/nginx.conf $INSTALL_DIR/conf/
checkReturnCode

#设置vscode的gdb配置。
VSCODE_GDB_DIR=$VSCODE_GDB_DIR/.vscode
rm -rf $VSCODE_GDB_DIR
mkdir -p $VSCODE_GDB_DIR
checkReturnCode

GDB_CFG_PATH=$VSCODE_GDB_DIR/launch.json
sed 's|aOut|'"$INSTALL_DIR"'/sbin/nginx|g' < $ROOT_DIR/doc/vscode.launch.json > $GDB_CFG_PATH
checkReturnCode

cat $GDB_CFG_PATH
checkReturnCode

printf "\n${COLOR_BLUE}******** done all ***********${COLOR_CLEAR}\n"
exit 0

