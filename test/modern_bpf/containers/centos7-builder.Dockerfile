FROM centos:7 AS build-stage

# we can pass a custom build directory, default is `build`
ARG BUILD_DIR="build"

# Install all the dependencies
WORKDIR /

RUN yum -y install centos-release-scl; \
    yum -y install devtoolset-8-gcc devtoolset-8-gcc-c++; \
    source scl_source enable devtoolset-8; \
    # We can remove `elfutils-libelf-devel-static` and `xz` when the PR on libelf bundled is merged
    yum install -y elfutils-libelf-devel-static xz; \
    yum install -y git wget make m4 kernel-devel-$(uname -r)

# With some previous cmake versions it fails when downloading `zlib` with curl in the libs building phase
RUN curl -L -o /tmp/cmake.tar.gz https://github.com/Kitware/CMake/releases/download/v3.22.5/cmake-3.22.5-linux-x86_64.tar.gz; \
    gzip -d /tmp/cmake.tar.gz; \
    tar -xpf /tmp/cmake.tar --directory=/tmp; \
    cp -R /tmp/cmake-3.22.5-linux-x86_64/* /usr; \
    rm -rf /tmp/cmake-3.22.5-linux-x86_64/

COPY . /libs
WORKDIR /libs

RUN mkdir -p ${BUILD_DIR}; \
    cd ${BUILD_DIR} && rm -f CMakeCache.txt && rm -rf CMakeFiles;
 
## TODO: we should set cmake options as an argument
RUN source scl_source enable devtoolset-8; \
    cd ${BUILD_DIR}; \
    cmake -DUSE_BUNDLED_DEPS=On -DBUILD_LIBSCAP_GVISOR=Off -DBUILD_BPF=True -DBUILD_LIBSCAP_MODERN_BPF=On -DCREATE_TEST_TARGETS=Off ..; \
    make scap-open

FROM scratch AS export-stage
COPY --from=build-stage /libs/build/libscap/examples/01-open/scap-open /
