#!/bin/bash

###########################################################
# auto script to recheck packet 
###########################################################
#set -o nounset
#set -o errexit

ROOT=`pwd`
INPUT_FILE_ROOT=$ROOT/check_packets
OUTPUT_FILE_ROOT=$ROOT/output_packets
STAND_FILE_ROOT=$ROOT/stand_packets
CMD=./ipdecap

INPUT_FILE=0
OUTPUT_FILE=0
STAND_FILE=0
FILE_TYPE=.pcap

rm -rf $OUTPUT_FILE_ROOT
mkdir -p $OUTPUT_FILE_ROOT

# neg output packet 
for (( i=1; i<13; i++)); do
	INPUT_FILE=$INPUT_FILE_ROOT/$i$FILE_TYPE
	OUTPUT_FILE=$OUTPUT_FILE_ROOT/$i$FILE_TYPE
	"$CMD" -i "$INPUT_FILE" -o "$OUTPUT_FILE"
done

STAND_FILE_SIZE=0
OUTPUT_FILE_SIZE=0
for (( i=1; i<13; i++)); do
	STAND_FILE_SIZE=`du -b $STAND_FILE_ROOT/$i$FILE_TYPE | awk '{print $1}'`
	OUTPUT_FILE_SIZE=`du -b $OUTPUT_FILE_ROOT/$i$FILE_TYPE | awk '{print $1}'` 

	if [ "$STAND_FILE_SIZE" != "$OUTPUT_FILE_SIZE" ]; then
		echo $STAND_FILE_SIZE $OUTPUT_FILE_SIZE
		echo "The OutPut Packet:$i is ERROR"
	fi
done



echo "###########################################"
echo "# deal is ok"
echo "###########################################"
