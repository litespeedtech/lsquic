#!/bin/bash
#
# Benchmark QUIC using LSQUIC http_client and other HTTP Benchmark tools.

# Variables
CLIENT_TYPE=''
CLIENT_PATH='http_client'
CLIENTS='1'
TRIALS='1'
HOST='www.example.com'
IP='192.168.0.1'
IP_PORT='192.168.0.1:8000'
REQ_PATH='/'
QUIC_VERSION='Q043'
CLIENT_OPTIONS='none'
IGNORE_OUT=''
REQUESTS='1'
CONNS='1'
MAXREQS='1'

function usage() {
cat <<EOF

Usage: lsqb-master.sh [-hTtCHSPpqlKrcmw]

Benchmark QUIC using LSQUIC http_client and other HTTP Benchmark tools.

Arguments:
 -h, --help             Show this help message and exit
 -T, --trials           Number of trials. (Default: 1)
 -t, --client_type      Type of client.
                        Supported QUIC options: http_client.
                        Supported HTTP options: curl, curl-caddy, ab, h2load.
                        (Default: http_client)
 -a, --client_path      Path to http_client. (Default: http_client)
 -C, --clients          Number of concurrent clients. (Default: 1)
 -H  --host             Name of server. (Default: www.example.com)
 -S, --ip_port          IP:PORT of domain. (Default: 192.168.0.1:8000)
 -P, --ip               IP of domain for curl-caddy. (Default: 192.168.0.1)
 -p, --path             Path of file. (Default: /)
 -q, --quic_version     QUIC version. (Default: Q043)
 -l, --options          Options for http_client. (Default: none)
 -K, --ignore_out       Ignore output for http_client. (Default: off)
 -r, --requests         Number of requests. (Default: 1)
 -c, --conns            Number of concurrent connections. (Default: 1)
 -m, --maxreqs          Maximum number of requests per connection. (Default: 1)
 -w, --concur           Maximum number of concurrent streams
                        within a single connection. (Default: 1)

EOF
}

function check_input() {
  while [[ "$1" != '' ]]; do
    case $1 in
      -T | --trials )       shift
                            TRIALS="$1"
                            ;;
      -t | --client_type)   shift
                            CLIENT_TYPE="$1"
                            ;;
      -a | --client_path)   shift
                            CLIENT_PATH="$1"
                            ;;
      -C | --clients )      shift
                            CLIENTS="$1"
                            ;;
      -H | --host )         shift
                            HOST="$1"
                            ;;
      -S | --ip_port )      shift
                            IP_PORT="$1"
                            ;;
      -P | --ip )           shift
                            IP="$1"
                            ;;
      -p | --path )         shift
                            PATH_STRING="$1"
                            REQ_PATH="${PATH_STRING//,/ }"
                            ;;
      -q | --quic_version ) shift
                            QUIC_VERSION="$1"
                            ;;
      -l | --options )      shift
                            CLIENT_OPTIONS="$1"
                            ;;
      -K | --ignore_out)    
                            IGNORE_OUT="-K"
                            ;;
      -r | --requests )     shift
                            REQUESTS="$1"
                            ;;
      -c | --conns )        shift
                            CONNS="$1"
                            ;;
      -m | --maxreqs )      shift
                            MAXREQS="$1"
                            ;;
      -w | --concur )       shift
                            CONCUR="$1"
                            ;;
      * )                   usage
                            exit 1
                            ;;
    esac
    shift
  done
}

function run_curl() {
  for (( i = 0; i < ${REQUESTS}; i++ )); do
    curl --header 'Host:$HOST' \
      -k https://${IP_PORT}/${REQ_PATH} \
      --output /dev/null --silent
  done
}

function run_curl_caddy() {
  for (( i = 0; i < ${REQUESTS}; i++ )); do
    curl --resolve ${HOST}:443:${IP} \
      -k https://${HOST}/${REQ_PATH} --output \
      /dev/null --silent
  done
}

function run_ab() {
  ab -n ${REQUESTS} -c ${CONNS} -k -X ${IP_PORT} \
  https://${HOST}/${REQ_PATH} &> /dev/null
}

function run_h2load() {
  h2load -n ${REQUESTS} -c ${CONNS} -m ${CONNS} \
  https://${IP_PORT}/${REQ_PATH} > /dev/null
}

function run_client() {
  if [[ "${CLIENT_OPTIONS}" == 'none' ]]; then
    CLIENT_OPTIONS=''
  fi
  ${CLIENT_PATH} ${IGNORE_OUT} \
    -H ${HOST} -s ${IP_PORT} \
    -p ${REQ_PATH} \
    -S rcvbuf=$[2000 * 2048] \
    -o support_tcid0=0 \
    -o version=${QUIC_VERSION} \
    ${CLIENT_OPTIONS} \
    -n ${CONNS} -r ${REQUESTS} -R ${MAXREQS} -w ${CONCUR}
}

function run_trials() {
  printf '\n'
  for (( i = 0; i < ${TRIALS}; i++ )); do
    START_TIME=$(date +%s.%3N)
    if [[ "${CLIENT_TYPE}" == 'curl' ]]; then
      for (( j = 0; j < ${CLIENTS}; j++ )); do
        run_curl &
      done
    elif [[ "${CLIENT_TYPE}" == 'curl-caddy' ]]; then
      for (( j = 0; j < ${CLIENTS}; j++ )); do
        run_curl_caddy &
      done
    elif [[ "${CLIENT_TYPE}" == 'ab' ]]; then
      for (( j = 0; j < ${CLIENTS}; j++ )); do
        run_ab &
      done
    elif [[ "${CLIENT_TYPE}" == 'h2load' ]]; then
      for (( j = 0; j < ${CLIENTS}; j++ )); do
        run_h2load &
      done
    else
      for (( j = 0; j < ${CLIENTS}; j++ )); do
        run_client &
      done
    fi
    wait
    END_TIME=$(date +%s.%3N)
    ELAPSED_TIME=$(awk "BEGIN {print ${END_TIME}-${START_TIME}}")
    printf ' %s, ' "${ELAPSED_TIME}"
  done
  printf '\n\n'
}

function main() {
  check_input "$@"
  run_trials
}

main "$@"
