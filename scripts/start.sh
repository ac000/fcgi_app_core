#!/bin/sh
#

IP="127.0.0.1"
PORT="9191"
PID="/tmp/app.pid"
APP="`pwd`/src/app"
CONFIG="`pwd`/config/app.cfg"

export LD_LIBRARY_PATH=`pwd`/src/libctemplate

cd src
spawn-fcgi -a $IP -p $PORT -P $PID -- $APP $CONFIG
