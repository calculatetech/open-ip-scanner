FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       avahi-daemon \
       build-essential \
       cmake \
       dbus \
       iproute2 \
       qt6-base-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src

RUN cmake -S /src -B /build \
        -DBUILD_TESTING=ON \
        -DCMAKE_BUILD_TYPE=Debug \
        -DOIS_MDNS_CONTROLLED_FIXTURE=ON \
    && cmake --build /build \
        --target mdns_resolver_test mdns_integration_test -j2

ENTRYPOINT ["/src/tests/fixtures/avahi/run-fixture.sh"]
