#!/bin/sh
# A relay is file-descriptor bound; raise the soft limit as far as allowed.
ulimit -n 65536 2>/dev/null || ulimit -n 10240 2>/dev/null || true
exec /app/roostr-relay
