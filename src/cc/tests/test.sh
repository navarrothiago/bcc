#!/bin/bash
cpu=${1:-0}
it=${2:-2}
for i in $(seq 1 $it) ; do
#for i in $(seq 1 10000) ; do
  echo -n "$i "
  for j in $(seq 1 500) ; do
    taskset --cpu-list $cpu echo "abaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &>/dev/null &
  done
done
echo
