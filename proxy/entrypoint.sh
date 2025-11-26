#!/bin/sh
set -e

# finally, nginx
exec nginx -g 'daemon off;'
