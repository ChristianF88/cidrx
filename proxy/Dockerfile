FROM nginx:stable-alpine

# install rsyslog for syslog buffering and dumb-init for proper signal handling\ nRUN apk add --no-cache rsyslog dumb-init
RUN apk add --no-cache dumb-init 

# Copy custom Nginx and rsyslog configs into the container
COPY default.conf /etc/nginx/conf.d/default.conf

# Include an entrypoint script to launch rsyslog and nginx
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose HTTP port
EXPOSE 80

# Use dumb-init as PID 1 and run our entrypoint
ENTRYPOINT ["/usr/bin/dumb-init", "--", "/entrypoint.sh"]
