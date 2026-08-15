# Reproducible PoC runner for Apache IoTDB v2.0.10.
#
# Stage 1 provides the EXACT release jars, taken from the official image itself —
# so the PoCs compile and run against the same bytecode the server runs. No jars
# are vendored into this repo; they are pulled from apache/iotdb:2.0.10-standalone
# at build time.
FROM apache/iotdb:2.0.10-standalone AS iotdb

FROM eclipse-temurin:17-jdk AS build
COPY --from=iotdb /iotdb/lib /iotdb-lib
WORKDIR /poc
COPY payload payload
COPY src src
RUN set -eu; \
    CP="$(ls /iotdb-lib/*.jar | tr '\n' ':')"; \
    echo "compiling malicious payloads..."; \
    javac -nowarn -cp "$CP" payload/org/apache/iotdb/raptor/RaptorPwn.java; \
    javac -nowarn payload/org/apache/iotdb/raptor/RaptorPlugin.java; \
    ( cd payload && jar cf /poc/raptorpwn.jar org/apache/iotdb/raptor/RaptorPwn.class ); \
    ( cd payload && jar cf /poc/raptorplugin.jar org/apache/iotdb/raptor/RaptorPlugin.class ); \
    echo "compiling PoCs..."; \
    mkdir -p out; \
    javac -nowarn -cp "$CP:src" -d out src/*.java; \
    printf '#!/bin/sh\nCP="$(ls /iotdb-lib/*.jar | tr "\\n" ":"):/poc/out"\nexec java -cp "$CP" "$@"\n' > /poc/j; \
    chmod +x /poc/j
ENTRYPOINT ["/poc/j"]
