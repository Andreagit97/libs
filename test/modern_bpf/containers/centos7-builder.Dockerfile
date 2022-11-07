FROM centos:7 AS build-stage

# To build libs you need to pass the cmake option
ARG CMAKE_OPTIONS=""

# Install all the dependencies
WORKDIR /

RUN yum -y install centos-release-scl; \
    yum -y install devtoolset-8-gcc devtoolset-8-gcc-c++; \
    source scl_source enable devtoolset-8; \
    yum install -y git wget make m4

# With some previous cmake versions it fails when downloading `zlib` with curl in the libs building phase
RUN curl -L -o /tmp/cmake.tar.gz https://github.com/Kitware/CMake/releases/download/v3.22.5/cmake-3.22.5-linux-$(uname -m).tar.gz; \
    gzip -d /tmp/cmake.tar.gz; \
    tar -xpf /tmp/cmake.tar --directory=/tmp; \
    cp -R /tmp/cmake-3.22.5-linux-$(uname -m)/* /usr; \
    rm -rf /tmp/cmake-3.22.5-linux-$(uname -m)/

COPY . /libs
WORKDIR /libs

RUN source scl_source enable devtoolset-8; \
    rm -rf build; \
    mkdir build && cd build; \
    cmake ${CMAKE_OPTIONS} ..; \
    make scap-open

FROM scratch AS export-stage

ARG DEST_BUILD_DIR="/build"

COPY --from=build-stage /libs/build/libscap/examples/01-open/scap-open /pack/
COPY --from=build-stage /libs/build/ ${DEST_BUILD_DIR}
