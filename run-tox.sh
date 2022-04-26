#! /bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Create virtualenv using tox and run pytest
# Accepts all args that pytest does
#
set -e
cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v tox >/dev/null; then
	echo >&2 "error: please install the python tox package"
	exit 1
fi

cmd=(tox -- "$@")
if [[ $(id -u) -ne 0 ]]; then
	echo >&2 "warning: running as non-root user, attempting sudo"
	exec sudo -- "${cmd[@]}"
else
	exec "${cmd[@]}"
fi
