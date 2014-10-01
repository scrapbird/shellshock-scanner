#!/bin/bash
for ((i = ${1}; i <= ${2}; i = i+=4))
do
	printf .
	wget "http://localhost:8080/search?q=inurl:cgi-bin filetype:sh&start=${i}" -q -O - >> output.txt
	x=$((i+4))
	echo ${x} > upto.txt
done
echo ""
