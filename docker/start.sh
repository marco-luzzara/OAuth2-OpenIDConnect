#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail
if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    echo 'Usage: ./start.sh
starts the db for the authorization server'
    exit
fi

cd "$(dirname "$0")"

main() {
    docker volume inspect mongo-data &> /dev/null || 
        ( echo "Creating mongo-data volume" && docker volume create mongo-data )
    docker-compose up --detach
}

main "$@"
