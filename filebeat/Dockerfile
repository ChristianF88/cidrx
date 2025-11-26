FROM docker.elastic.co/beats/filebeat:8.5.0
USER root

# install envsubst
RUN apt-get update && \
    apt-get install -y --no-install-recommends gettext-base && \
    rm -rf /var/lib/apt/lists/*

# first, disable nginx in the *original* config
RUN filebeat modules disable nginx

# now overwrite with your custom filebeat.yml
COPY filebeat.yml /usr/share/filebeat/filebeat.yml

ENTRYPOINT ["sh","-c",\
    "envsubst < /usr/share/filebeat/filebeat.yml > /usr/share/filebeat/generated.yml && \
     exec filebeat -e -c /usr/share/filebeat/generated.yml"]
