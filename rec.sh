#!/bin/sh

TS="$1"
OF="`pwd`/recording.mp4"

while [ "`date +%s`" -lt "$TS" ]; do
	sleep 0.1
done

#echo RECORDING...
ffmpeg -y -loglevel quiet -f fbdev -framerate 24 -i /dev/fb0 \
	-vf crop=1280:720:0:0 -pix_fmt yuv420p "$OF" &

"src/$2.py"
