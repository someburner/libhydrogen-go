#!/bin/bash

case "$1" in
	"fmt") echo "Formatting all files..."
		for f in $(find . -name "*.go"); do
			ignore=$(echo "$f" | grep '.local')
			! [[ -z $ignore ]] && echo "ignoring file $f" && continue;
			go fmt $f;
		done
	exit $?;
	;;
	*) echo "invalid arg";
	exit 1;
	;;
esac


exit 0;
