#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail
if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    echo 'Usage: ./stop.sh
stops the db and session store for the authorization server'
    exit
fi

cd "$(dirname "$0")"

main() {
    docker-compose down
}

main "$@"
