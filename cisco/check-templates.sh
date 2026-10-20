#!/usr/bin/env bash
# IOS only treats "!" as a comment at the START of a line. A trailing "! note" after a command
# becomes part of the command (e.g. part of an enable secret). This fails if any template has one.
cd "$(dirname "$0")/templates" || exit 1
bad=$(grep -nE '^[[:space:]]*[^![:space:]].*!' *.txt | grep -vE 'banner motd #[^#]*#$')
if [ -n "$bad" ]; then echo "$bad"; echo "FAIL: $(echo "$bad" | wc -l) line(s) with trailing ! comments"; exit 1; fi
echo "OK: no trailing comments"
