#! /bin/sh

exec tox -- --log-cli-level=DEBUG -s "$@"
