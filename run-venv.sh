#! /bin/bash
#
# Create virtualenv using tox and run pytest
# Accepts all args that pytest does
#
set -e

maybe_sudo=
if [[ $(id -u) -ne 0 ]]; then
	echo >&2 "warning: running as non-root user, attempting sudo"
	# sudo -E to use the virtualenv:
	maybe_sudo="sudo -E"
fi
cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ -d venv ]]; then
	echo >&2 "Using existing $(readlink -f venv)"
	. venv/bin/activate
else
	echo >&2 "Creating $(readlink -f venv)"
	python3 -m venv venv
	. venv/bin/activate
	pip install wheel
	pip install -r requirements.txt
fi
exec $maybe_sudo pytest -s --log-cli-level=DEBUG "$@"
