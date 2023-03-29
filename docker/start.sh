#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail
if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    echo 'Usage: ./start.sh
starts the db and session store for the authorization server'
    exit
fi

cd "$(dirname "$0")"

main() {
    local possibly_new_volumes='auth-server-mongo-data auth-server-redis-data client-redis-data resource-server-mongo-data'
    for vol in $possibly_new_volumes
    do
        docker volume inspect "$vol" &> /dev/null || 
            ( echo "Creating $vol volume" && docker volume create "$vol" )
    done
    docker-compose up --detach

    sleep 30

    docker cp auth_server/db_seed.js auth_server_db:/home/db_seed.js
    docker exec -it auth_server_db \
        mongosh "mongodb://admin:admin@localhost:27017/demo?authSource=admin" --file /home/db_seed.js

    docker cp resource_server/db_seed.js resource_server_db:/home/db_seed.js
    docker exec -it resource_server_db \
        mongosh "mongodb://admin:admin@localhost:27017/demo?authSource=admin" --file /home/db_seed.js
}

main "$@"
