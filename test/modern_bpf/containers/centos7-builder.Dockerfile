FROM centos:7 AS build-stage

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

# Copy the build context under root. The checkout of the repo is made outside of this container
COPY . /libs
WORKDIR /libs

# Move the modern probe into the build directory
RUN rm -rf build; \
    mkdir build && cd build; \
    mv ./../skel_dir ./

## TODO: we should set cmake options as an argument
RUN source scl_source enable devtoolset-8; \
    cd build; \
    cmake -DUSE_BUNDLED_DEPS=On -DBUILD_LIBSCAP_GVISOR=Off -DBUILD_BPF=True -DBUILD_LIBSCAP_MODERN_BPF=On -DUSE_BUNDLED_MODERN_PROBE=Off -DCREATE_TEST_TARGETS=Off ..; \
    make scap-open

FROM scratch AS export-stage
COPY --from=build-stage /libs/build/libscap/examples/01-open/scap-open /
