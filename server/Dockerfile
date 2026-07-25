# Stage 1 — build with Maven + JDK 25 (source build inside Docker; no prebuilt jar needed)
FROM maven:3.9-eclipse-temurin-25@sha256:7e461cec477077c1d9e50b13df8aef9018764410f4c4cd7c34803f10c4c99e4c AS build

WORKDIR /build

# Pre-fetch deps in a separate layer so source changes don't retrigger downloads
COPY server/pom.xml .
RUN mvn dependency:go-offline -q

COPY server/src ./src
RUN mvn package -DskipTests -q

# The consequence-diff authoring path evaluates staged bundles with the exact pinned Cerbos binary.
# This is copied into the runtime image; it does not talk to or swap the live PDP policy pointer.
FROM ghcr.io/cerbos/cerbos:0.53.0@sha256:c3fe64202e3793b7e9c41c5cbfcf390a51fb28ebce0a7d70754155e70db839c4 AS cerbos-runtime

# Stage 2 — lean runtime (JRE + wget for healthcheck)
FROM eclipse-temurin:25-jre-alpine@sha256:28db6fdf60e38945e43d840c0333aeaec66c15943070104f7586fd3c9d1665b0

LABEL maintainer="Axiom Platform"
LABEL description="Axiom — OIDC provider, identity administration, and platform policy studio"

RUN apk add --no-cache wget

COPY --from=cerbos-runtime /cerbos /usr/local/bin/cerbos

WORKDIR /app
COPY --from=build /build/target/iam-service-*.jar app.jar
COPY platform-policy /app/platform-policy
COPY platform-contract /app/platform-contract

EXPOSE 8084

# -XX:+ZGenerational was removed in JDK 24; passing it to a 25 JVM aborts startup.
# ZGC is generational by default from 23 onward, so -XX:+UseZGC alone is equivalent.
ENTRYPOINT ["java", \
    "-XX:+UseZGC", \
    "-Djava.security.egd=file:/dev/./urandom", \
    "-jar", \
    "app.jar"]
