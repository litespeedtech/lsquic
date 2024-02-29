#!/bin/bash
#
# run_endpoint.sh -- QUIC Interop Runner script for lsquic
#

/setup.sh

if [ "$ROLE" == "client" ]; then
    # Wait for the simulator to start up.
    /wait-for-it.sh sim:57832 -s -t 30
fi

echo TEST_PARAMS: $TEST_PARAMS
echo REQUESTS: "'$REQUESTS'"
eval $(perl <<'PERL'
    @paths = split /\s+/, $ENV{REQUESTS};
    s~^https?://[^/]+~-p ~ for @paths;
    print "PATHS='@paths'\n";
    $server = $ENV{REQUESTS};
    $server =~ s~^https?://~~;
    $server =~ s~/.*~~;
    ($server, $port) = split /:/, $server;
    print "SERVER=$server\n";
    print "PORT=$port\n";
    print "N_REQS=", scalar(@paths), "\n";
    print "N_reqs=", scalar(@paths), "\n";
    if (@paths > 100) {
        print "W=100\n";
    } else {
        print "W=1\n";
    }
PERL
)
echo paths: $PATHS
echo server: $SERVER
echo port: $PORT

# lsquic command-line tools create one file per connection when -G option
# is used.  Here we make a copy and give it required name.
#
function maybe_create_keylog() {
    local NAME=/logs/keys.log
    if ls /logs/*.keys; then
        # There may be more than one of these, as one file is created per
        # connection.
        cat /logs/*.keys > $NAME
    fi
    if [ -f $NAME ]; then
        echo $NAME exists
    else
        echo $NAME does not exit
    fi
}

if [ "$ROLE" = server ]; then
    if [ ! -z "$TESTCASE" ]; then
        case "$TESTCASE" in
            http3)
                VERSIONS='-o version=h3-29 -o version=h3'
                ;;
            v2)
                VERSIONS='-o version=h3-v2 -o version=h3 -Q hq-interop'
                ;;
            handshake|transfer|longrtt|resumption|blackhole|multiconnect|chacha20|zerortt)
                VERSIONS='-o version=h3-29 -o version=h3 -o scid_iss_rate=0 -Q hq-interop'
                ;;
            retry)
                VERSIONS='-o version=h3-29 -o version=h3 -o srej=1 -Q hq-interop'
                FORCE_RETRY=1
                ;;
            ecn)
                VERSIONS='-o version=h3-29 -o version=h3 -Q hq-interop'
                ECN='-o ecn=1'
                ;;
            *) exit 127 ;;
        esac
    fi
    echo SERVER_PARAMS: $SERVER_PARAMS
    exec env LSQUIC_FORCE_RETRY=$FORCE_RETRY /usr/bin/http_server $VERSIONS $ECN \
        -c server,/certs/cert.pem,/certs/priv.key \
        -c server4,/certs/cert.pem,/certs/priv.key \
        -c server6,/certs/cert.pem,/certs/priv.key \
        -c server46,/certs/cert.pem,/certs/priv.key \
        -s ::0:443 -s 0.0.0.0:443 -s 193.167.100.100:12345 \
        -r /www -L debug 2>/logs/$TESTCASE.out
elif [ "$ROLE" = debug-server ]; then
    exec /usr/bin/http_server $SERVER_PARAMS
elif [ "$ROLE" = client ]; then
    if [ ! -z "$TESTCASE" ]; then
        case "$TESTCASE" in
            http3)
                VERSIONS='-o version=h3'
                ;;
            v2)
                VERSIONS='-o version=h3-v2 -o version=h3 -Q hq-interop'
                ;;
            handshake|transfer|longrtt|retry|multiplexing|blackhole)
                VERSIONS='-o version=h3 -Q hq-interop'
                ;;
            multiconnect)
                VERSIONS='-o version=h3 -Q hq-interop'
                N_REQS=1
                ;;
            ecn)
                VERSIONS='-o version=h3 -Q hq-interop'
                ECN='-o ecn=1'
                ;;
            resumption)
                VERSIONS='-o version=h3 -Q hq-interop'
                RESUME='-0 /logs/resume.file'
                ;;
            *) exit 127 ;;
        esac
    fi
    echo CLIENT_PARAMS: $CLIENT_PARAMS
    if [ "$TESTCASE" = resumption ]; then
        # Fetch first file:
        /usr/bin/http_client $VERSIONS -s $SERVER:$PORT $PATHS \
            -r 1 -R 1 $RESUME \
            -B -7 /downloads -G /logs \
            -L debug 2>/logs/$TESTCASE-req1.out || exit $?
        PATHS=`echo "$PATHS" | sed 's~-p /[^ ]* ~~'`
        N_REQS=1
        N_reqs=1
        W=1
        echo "first request successful, new args: $N_REQS; $N_reqs; $PATHS"
    fi
    /usr/bin/http_client $VERSIONS -s $SERVER:$PORT $PATHS \
        -r $N_reqs -R $N_REQS -w $W $ECN $RESUME \
        -B -7 /downloads -G /logs \
        -L debug 2>/logs/$TESTCASE.out
    EXIT_CODE=$?
    maybe_create_keylog
    sync
    exit $EXIT_CODE
else
    echo hi
    exit 127
fi
