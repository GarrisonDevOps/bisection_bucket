#!/bin/bash
# This can be used to create user, database, schema and grant the required permissions.
# This script can handle multiple execution and not with "already exists" error. An entity will get created only if it does not exist.
# NOTE : 1. This expects current linux user to be admin user in postgreSQL (this is the case with 'postgres' user)
#        2. Execute this by logging as postgres or any other user with similar privilege
#        3. This files needs be executed from a location which postgres (or the admin user which will be used) has access to. (/opt can be used)
#
#        su postgres -c "POSTGRES_PATH=/path/to/postgres/bin PGPASSWORD=postgres bash ./createPostgresUsers.sh"

POSTGRES_LABEL="Postgres"

#This content is copied from _logger.sh in the commons repo. - BEGIN

cClear="\e[0m"
cBlue="\e[38;5;69m"
cRedDull="\e[1;31m"
cYellow="\e[1;33m"
cRedBright="\e[38;5;197m"


_loggerGetMode() {
    local MODE="$1"
    case $MODE in
    INFO) 
        printf "${cBlue}%s%-5s%s${cClear}" "[" "${MODE}" "]"
    ;;
    DEBUG)
        printf "%-7s" "[${MODE}]"
    ;;
    WARN)
        printf "${cRedDull}%s%-5s%s${cClear}" "[" "${MODE}" "]"
    ;;
    NOTE)
        printf "%s${cYellow}%-5s%s${cClear}" "[" "${MODE}" "]"
    ;;
    ERROR)
        printf "${cRedBright}%s%-5s%s${cClear}" "[" "${MODE}" "]"
    ;;
    esac
}

# Capitalises the first letter of the message
_loggerGetMessage() {
    local originalMessage="$*"
    local firstChar=$(echo "${originalMessage:0:1}" | awk '{ print toupper($0) }')
    local resetOfMessage="${originalMessage:1}"
    echo "$firstChar$resetOfMessage"
}

# The spec also says content should be left-trimmed but this is not necessary in our case. We don't reach the limit.
_loggerGetStackTrace() {
    printf "%s%-30s%s" "[" "$1:$2" "]"
}

_loggerGetThread() {
    printf "%s" "[main]"
}

_loggerGetServiceType() {
    printf "%s%-5s%s" "[" "shell" "]"
}

#Trace ID is not applicable to scripts
_loggerGetTraceID() {
    printf "%s" "[]"
}

_loggerGetTimestamp() {
    local OS_TYPE=$(uname)
    if [ "${OS_TYPE}" == "Darwin" ]; then
        echo -n $(date -u +%FT%TZ) #Mac does not support milli seconds
    else
        echo -n $(date -u +%FT%T.%3NZ)
    fi
}

logger() {
    if [ -z "$CONTEXT" ]
    then
        CONTEXT=$(caller)
    fi
    local MESSAGE="$1"
    local MODE=${2-"INFO"}
    local SERVICE_TYPE="script"
    local TRACE_ID=""
    local THREAD="main"
    
    local CONTEXT_LINE=$(echo "$CONTEXT" | awk '{print $1}')
    local CONTEXT_FILE=$(echo "$CONTEXT" | awk -F"/" '{print $NF}')
    
    # As per logging Standards: https://docs.google.com/document/d/1JFNpS0OGSh6hCf8uCCrXOcxrVlXlbtZH5POFoW2QC8Y
    printf "%s\n" "$(_loggerGetTimestamp) $(_loggerGetServiceType) $(_loggerGetMode $MODE) $(_loggerGetTraceID) $(_loggerGetStackTrace $CONTEXT_FILE $CONTEXT_LINE) $(_loggerGetThread) - $(_loggerGetMessage $MESSAGE)"
   
    CONTEXT=
}

#This content is copied from _logger.sh in the commons repo. - END

errorExit() {
    echo; echo -e "\033[31mERROR:\033[0m $1"; echo
    exit 1
}

# Create user if it does not exist
createUser(){
    local user=$1
    local pass=$2

    [ ! -z ${user} ] || errorExit "user is empty"
    [ ! -z ${pass} ] || errorExit "password is empty"

    ${PSQL} $POSTGRES_OPTIONS -tAc "SELECT 1 FROM pg_roles WHERE rolname='${user}'" | grep -q 1 1>/dev/null || \
    ${PSQL} $POSTGRES_OPTIONS -c "CREATE USER ${user} WITH PASSWORD '${pass}';" 1>/dev/null || \
    errorExit "Failed creating user ${user} on PostgreSQL"
}

# Create database if it does not exist
createDB(){
    local db=$1
    local user=$2

    [ ! -z ${db}   ] || errorExit "db is empty"
    [ ! -z ${user} ] || errorExit "user is empty"

    if ! ${PSQL} $POSTGRES_OPTIONS -lqt | cut -d \| -f 1 | grep -qw ${db} 1>/dev/null; then
        ${PSQL} $POSTGRES_OPTIONS -c "CREATE DATABASE ${db} WITH ENCODING='UTF8' LC_COLLATE='en_US.utf8' LC_CTYPE='en_US.utf8' TABLESPACE=${DB_TABLESPACE} template template0;" 1>/dev/null || errorExit "Failed creating db ${db} on PostgreSQL"
    fi
}

# Create schema if it does not exist
createSchema(){
    local schema=$1
    local db=$2
    local user=$3

    [ ! -z ${schema} ] || errorExit "schema is empty"
    [ ! -z ${db}     ] || errorExit "db is empty"
    [ ! -z ${user}   ] || errorExit "user is empty"

    PGOPTIONS='--client-min-messages=warning' ${PSQL} $POSTGRES_OPTIONS --dbname="${db}" -qc "CREATE SCHEMA IF NOT EXISTS ${schema} AUTHORIZATION ${user}" 1>/dev/null
}

postgresIsNotReady() {
    attempt_number=${attempt_number:-0}
	${PSQL} $POSTGRES_OPTIONS --version > /dev/null 2>&1
    outcome1=$?

    # Execute a simple db function to verify if mongo is up and running
    ${PSQL} $POSTGRES_OPTIONS -l > /dev/null 2>&1
    outcome2=$?
    if [[ $outcome1 -eq 0 ]] && [[ $outcome2 -eq 0  ]]; then
        return 0
    fi

    if [ $attempt_number -gt 10 ]; then
        errorExit "Unable to proceed. $POSTGRES_LABEL is not reachable. This can occur if the service is not running \
or the port is not accepting requests at $DB_PORT (host : $DB_HOST). Gave up after $attempt_number attempts"
    fi

    let "attempt_number=attempt_number+1"
    return 1
}

init(){
    if [[ -z $POSTGRES_PATH ]]; then
        ${PSQL} --version 2>/dev/null || { echo >&2 "\"${PSQL}\" is not installed or not available in path"; exit 1; }
    fi

    logger "Waiting for $POSTGRES_LABEL to get ready using the commands: \"${PSQL} $POSTGRES_OPTIONS --version\" & \"${PSQL} $POSTGRES_OPTIONS -l\""
    attempt_number=0
    while ! postgresIsNotReady
    do
            sleep 5
            echo -n '.'
    done
    echo ""
    logger "$POSTGRES_LABEL is ready. Executing commands"
}

setupDB(){
    local user=$1
    local pass=$2
    local db=$3
    local schema=$4

    createUser "${user}" "${pass}"    
    createDB "${db}" "${user}"
    
    ${PSQL} $POSTGRES_OPTIONS -c "GRANT ALL PRIVILEGES ON DATABASE ${db} TO $user" 1>/dev/null;
    ${PSQL} $POSTGRES_OPTIONS -c "ALTER DATABASE ${db} OWNER TO $user" 1>/dev/null;
    ${PSQL} $POSTGRES_OPTIONS -c "ALTER SCHEMA public OWNER TO ${user} --dbname=${db}" 1>/dev/null;

    if [ ! -z "${schema}" ]; then
        createSchema "${schema}" "${db}" "${user}"
        ${PSQL} $POSTGRES_OPTIONS -c "GRANT ALL ON SCHEMA ${schema} TO ${user}" --dbname="${db}" 1>/dev/null;
    fi
}

### Following are the postgres details being setup for each service.
##  Common details
: ${DB_PORT:=5432}
: ${DB_NAME:="xraydb"}
: ${DB_SSLMODE:="false"}
: ${DB_TABLESPACE:="pg_default"}
: ${DB_HOST:="localhost"}
: ${DB_USERNAME:="xray"}
: ${DB_PASSWORD:="xray"}

# If DB_HOST is set to container name, set it as localhost as this script is expected to run within the container
if [[ $DB_HOST == "postgres" ]]; then
    DB_HOST="localhost"
fi

[[ -z "${POSTGRES_PATH}" ]] && PSQL=psql || PSQL=${POSTGRES_PATH}/psql
POSTGRES_OPTIONS="--host=${DB_HOST} --port=${DB_PORT}"

init
setupDB "${DB_USERNAME}" "${DB_PASSWORD}" "${DB_NAME}"
logger "$POSTGRES_LABEL setup is now complete"

exit 0
