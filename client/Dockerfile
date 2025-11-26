# Use the ultra-slim curl-only image
FROM curlimages/curl:latest

# Build-time defaults (can be overridden with --build-arg)
ARG TARGET_URL=http://nginx:80/
ARG INTERVAL=1

# Expose them as environment variables
ENV TARGET_URL=${TARGET_URL}
ENV INTERVAL=${INTERVAL}

# Loop: curl the URL, then sleep for $INTERVAL seconds
ENTRYPOINT ["sh","-c","\
  echo \"Starting continuous curl to $TARGET_URL every $INTERVAL seconds...\";\
  while true; do \
    curl -s -o /dev/null --fail --show-error \"$TARGET_URL\" && echo \"[$(date)] OK\" || echo \"[$(date)] FAIL\";\
    sleep \"$INTERVAL\";\
  done"]
