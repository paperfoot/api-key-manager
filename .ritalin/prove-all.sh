#!/bin/sh
cd /Users/biobook/Projects/api-key-manager
for n in 001 002 003 004 005 006 007 008 009 010 011 012 013 014; do
  out=$(ritalin prove "O-$n" 2>&1)
  verdict=$(echo "$out" | grep -oE '"verdict": "[a-z]+"' | head -1)
  printf "O-%s  %s\n" "$n" "$verdict"
done
