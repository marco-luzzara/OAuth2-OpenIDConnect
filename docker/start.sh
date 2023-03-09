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
    local mongo_data_volume_name="mongo-data"
    local redis_data_volume_name="redis-data"
    docker volume inspect "$mongo_data_volume_name" &> /dev/null || 
        ( echo "Creating $mongo_data_volume_name volume" && docker volume create "$mongo_data_volume_name" )
    docker volume inspect "$redis_data_volume_name" &> /dev/null || 
        ( echo "Creating $redis_data_volume_name volume" && docker volume create "$redis_data_volume_name" )
    docker-compose up --detach

    sleep 30

    docker cp auth_server/db_seed.js auth_server_db:/home/db_seed.js
    docker exec -it auth_server_db \
        mongosh "mongodb://admin:admin@localhost:27017/demo?authSource=admin" --file /home/db_seed.js
}

main "$@"
