#!/bin/bash

WEB_HASH=`${1}/src/webget httpbin.org /base64/SGVsbG93IHdvcmxk | tee /dev/stderr | tail -n 1`
CORRECT_HASH="Hellow world"

if [ "${WEB_HASH}" != "${CORRECT_HASH}" ]; then
    echo ERROR: webget returned output that did not match the test\'s expectations
    exit 1
fi
exit 0
