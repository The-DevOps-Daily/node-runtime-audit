#!/bin/sh
# A stand-in for the docker CLI: five running containers, one with escape codes in its name.
case "$1" in
ps)
  printf 'aaaaaaaaaaaa0000000000000000000000000000000000000000000000000000\tshop-api\tnode:22-alpine\n'
  printf 'bbbbbbbbbbbb0000000000000000000000000000000000000000000000000000\tcache\tredis:8\n'
  printf 'cccccccccccc0000000000000000000000000000000000000000000000000000\tdistroless-app\tregistry.example.com/app:1\n'
  printf 'dddddddddddd0000000000000000000000000000000000000000000000000000\tnew-api\tnode:24-slim\n'
  printf 'eeeeeeeeeeee0000000000000000000000000000000000000000000000000000\tevil\033[2Jname\timg\033]0;t\007\n'
  ;;
exec)
  case "$*" in
  *aaaaaaaaaaaa*) echo v22.22.0 ;;
  *dddddddddddd*) echo v24.22.1 ;;
  *eeeeeeeeeeee*) echo v24.22.1 ;;
  *) echo "exec: node: not found" >&2; exit 127 ;;
  esac
  ;;
inspect)
  case "$*" in
  *aaaaaaaaaaaa*) printf 'PATH=/usr/local/bin\nNODE_VERSION=22.22.0\nYARN_VERSION=1.22.22\n' ;;
  *cccccccccccc*) printf 'PATH=/nodejs/bin\nNODE_VERSION=24.14.0\n' ;;
  *dddddddddddd*) printf 'NODE_VERSION=24.22.1\n' ;;
  *) printf 'PATH=/usr/local/bin\n' ;;
  esac
  ;;
esac
