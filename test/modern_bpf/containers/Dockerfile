FROM ubuntu:22.04 AS runner

RUN apt update; \
    apt install -y libelf-dev

COPY ./bpf_test /usr/local/bin/bpf_test

CMD ["/usr/local/bin/bpf_test", "--gtest_filter='SyscallExit.mkdirX'"]
