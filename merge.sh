#!/bin/zsh

# trace from shut1
FILE1=$1
# trace from shut2
FILE2=$2

# dir containing the normal merge
merge_dir=$3

# dir containing the txt offset
offsets=$4

adjusted_dir=$5

# dir containing the adjusted merge
merge_adjusted_dir=$6

day="${FILE1:0:19}"
ext="_merge.pcap"

mergecap -w "$merge_dir/$day.pcap" $FILE1 $FILE2

offset="$offsets/$day""_merge.txt"
adjusted="$adjusted_dir/${FILE1:0:25}_adjusted.pcap"

$(python compute_offset.py -f1 "$merge_dir/$day.pcap" -f2 $FILE1 -o "$offset")

$(./bin/shift_time -i "$FILE1" -f "$offset" -o "$adjusted")

mergecap -w "$merge_adjust_dir/$day$ext" $adjusted $FILE2

reordercap -n "$merge_adjusted_dir/$day$ext" "$merge_adjusted_dir/$day""_merge_re.pcap"

rm "$merge_adjusted_dir/$day$ext"

mv "$merge_adjusted_dir/$day""_merge_re.pcap" "$merge_adjusted_dir/$day$ext"
