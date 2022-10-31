FROM ubuntu:18.04 AS build-stage

WORKDIR /

RUN apt update; \
    apt install -y --no-install-recommends ca-certificates cmake build-essential git libelf-dev wget lsb-release software-properties-common gnupg libcap-dev

RUN wget https://apt.llvm.org/llvm.sh; \
    chmod +x llvm.sh; \
    ./llvm.sh 12; \
    update-alternatives --install /usr/bin/clang clang /usr/bin/clang-12 90; \
    update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-12 90

RUN git clone https://github.com/libbpf/bpftool.git --branch v6.7.0 --single-branch; \
    cd bpftool; \
    git submodule update --init; \
    cd src && make install; \
    rm -rf /bpftool

# Copy the build context under root. The checkout of the repo is made outside of this container
COPY . /libs
WORKDIR /libs

# we should set cmake options as an argument
RUN mkdir build && cd build; \
    cmake -DUSE_BUNDLED_DEPS=On -DBUILD_LIBSCAP_GVISOR=Off -DBUILD_BPF=True -DBUILD_LIBSCAP_MODERN_BPF=On -DBUILD_MODERN_BPF_TEST=On ..; \
    make bpf_test

FROM scratch AS export-stage
COPY --from=build-stage /libs/build/test/modern_bpf/bpf_test /
