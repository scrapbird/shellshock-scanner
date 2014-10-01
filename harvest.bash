#!/bin/bash
for ((i = ${1}; i <= ${2}; i++))
do
	echo .
	wget "http://localhost:8080/search?q=inurl:cgi-bin filetype:sh&start=${i}" -q -O - >> output.txt
	echo ${i} > upto.txt
done
