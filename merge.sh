#!/bin/zsh


FILE1=$1
FILE2=$2

day="${FILE1:0:19}"
ext="_merge.pcap"

mergecap -w "$day.pcap" $FILE1 $FILE2

offset="$day""_merge.txt"
adjusted="${FILE1:0:25}_adjusted.pcap"

$(python compute_offset.py -f1 "$day.pcap" -f2 $FILE1 -o "$offset")

$(./bin/shift_time -i "$FILE1" -f "$offset" -o "$adjusted")

mergecap -w "$day$ext" $adjusted $FILE2

reordercap -n "$day$ext" "$day""_merge_re.pcap"

rm "$day$ext"

mv "$day""_merge_re.pcap" "$day$ext"
