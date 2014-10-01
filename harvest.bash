#!/bin/bash
for ((i = ${1}; i <= ${2}; i++))
do
	printf .
	set x = $i * 4
	wget "http://localhost:8080/search?q=inurl:cgi-bin filetype:sh&start=${x}" -q -O - >> output.txt
	echo ${i} > upto.txt
done
