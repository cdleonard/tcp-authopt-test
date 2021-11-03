#! /bin/bash
# SPDX-License-Identifier: GPL-2.0

print_help()
{
    cat >&2 <<MSG
$(basename "$0"): Create virtualenv using pip and run pytest

Accepts all options that pytest does, run \`\`$(basename $0) --pytest-help\`\` to
see help from pytest itself.

If current user is not already root this script with attempt sudo.
MSG
}

set -e
if [[ $1 == -h || $1 == --help ]]; then
    print_help
    exit 64
fi
if [[ $1 == --pytest-help ]]; then
	shift
	set -- --help "$@"
fi

cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ -d venv ]]; then
	echo >&2 "Using existing $(readlink -f venv)"
else
	echo >&2 "Creating $(readlink -f venv)"
	python3 -m venv ./venv
	(
		. venv/bin/activate
		pip install wheel
		pip install -r requirements.txt
	)
fi

cmd=(pytest -s --log-cli-level=DEBUG "$@")
if [[ $(id -u) -ne 0 ]]; then
	echo >&2 "warning: running as non-root user, attempting sudo"
	# sudo -E to use the virtualenv:
	cmd=(sudo bash -c ". venv/bin/activate;$(printf " %q" "${cmd[@]}")")
	exec "${cmd[@]}"
else
	. venv/bin/activate
	exec "${cmd[@]}"
fi
