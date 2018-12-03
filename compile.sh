#!/bin/sh

CUR_DIR=$(pwd)
ROOT_DIR=$(dirname $(readlink -f $0))
cd $ROOT_DIR
chmod a+x compile.sh

BUILD_DIR=~/buildGbRtp
INSTALL_DIR=$BUILD_DIR/install
VSCODE_GDB_DIR=$ROOT_DIR
DEBUG_FLAGS="-g -O0"
DEBUG_KEY="debug"
OPTIMIZE="no"

################################################## compile
compileLibRtmp() {
	rm -rf $BUILD_DIR/rtmpdump-2.3
	tar zxf $ROOT_DIR/doc/rtmpdump-2.3.tgz -C $BUILD_DIR
	cd $BUILD_DIR/rtmpdump-2.3

	make OPT="$DEBUG_FLAGS"

	cat > $ROOT_DIR/dep.make <<END
		libRtmp=$BUILD_DIR/rtmpdump-2.3
END

	echo "done to build libRtmp"
	echo
}

compileApp() {
	cd $ROOT_DIR
	rm -rf *.out
	make ver=$DEBUG_KEY opti=$OPTIMIZE
	echo "done to build app"
}

################################################## get argument
for option   #option是内置变量，代表了当前脚本程序的参数集合(不含脚本程序名)
do
	case "$option" in
		*=*) value=`echo "$option" | sed -e 's/[-_a-zA-Z0-9]*=//'` ;;
		*) value="" ;;
	esac
	case "$option" in
		release=*) releaseOpt="$value" ;;
		apponly=*) appOnly="$value" ;;
		appOnly=*) appOnly="$value" ;;
	esac
done

echo "releaseOpt=$releaseOpt appOnly=$appOnly"
echo "**************************************************"
sleep 3

################################################## we compile nginx only and simply
if [ ! -z $releaseOpt ]; then
	DEBUG_FLAGS=
	DEBUG_KEY=
	OPTIMIZE="yes"
fi

if [ ! -z $appOnly ]; then
	compileApp
	exit 0
fi

################################################## 第一次编译，compile all
rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR

#检测：编译目录是否创建成功，是否能新建文件。
echo "temp" > $BUILD_DIR/.heb1
if [  $? -ne 0 ];then
	echo "fail to test: can not create new file in $BUILD_DIR"
	exit 1
fi
rm -rf $BUILD_DIR/.heb*

#编译
compileLibRtmp
cd $ROOT_DIR/
make clean
compileApp

#设置vscode的gdb配置。
VSCODE_GDB_DIR=$VSCODE_GDB_DIR/.vscode
rm -rf $VSCODE_GDB_DIR
mkdir -p $VSCODE_GDB_DIR
GDB_CFG_PATH=$VSCODE_GDB_DIR/launch.json
sed 's|aOut|'"$ROOT_DIR"'/rtpServer.out|g' < $ROOT_DIR/doc/vscode.launch.json > $GDB_CFG_PATH
cat $GDB_CFG_PATH
