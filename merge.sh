#!/bin/sh


FILE1=$1
FILE2=$2

day="${FILE1:0:16}"

mergecap -w "$day.pcap" $FILE1 $FILE2

offset="merge_$day.txt"
adjusted="${FILE1:0:16}_adjusted.pcap"

$(python compute_offset.py -f1 "$day.pcap" -f2 $FILE1 -o "$offset")

$(./bin/shift_time -i "$FILE1" -f "$offset" -o "$adjusted")

mergecap -w "$day""_merge.pcap" $adjusted $FILE2

reordercap -n "$day""_merge.pcap" "$day""_merge_re.pcap"




