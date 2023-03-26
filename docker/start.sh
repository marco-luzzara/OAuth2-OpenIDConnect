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
    local auth_server_mongo_data_volume_name="auth-server-mongo-data"
    local auth_server_redis_data_volume_name="auth-server-redis-data"
    local client_data_volume_name="client-redis-data"
    local resource_server_mongo_data_volume_name="resource-server-mongo-data"
    docker volume inspect "$auth_server_mongo_data_volume_name" &> /dev/null || 
        ( echo "Creating $auth_server_mongo_data_volume_name volume" && docker volume create "$auth_server_mongo_data_volume_name" )
    docker volume inspect "$auth_server_redis_data_volume_name" &> /dev/null || 
        ( echo "Creating $auth_server_redis_data_volume_name volume" && docker volume create "$auth_server_redis_data_volume_name" )
    docker volume inspect "$client_data_volume_name" &> /dev/null || 
        ( echo "Creating $client_data_volume_name volume" && docker volume create "$client_data_volume_name" )
    docker volume inspect "$resource_server_mongo_data_volume_name" &> /dev/null || 
        ( echo "Creating $resource_server_mongo_data_volume_name volume" && docker volume create "$resource_server_mongo_data_volume_name" )
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
