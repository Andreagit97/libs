FROM ubuntu:22.04 AS runner

COPY ./bpf_test /usr/local/bin/bpf_test

# This is put here to avoid running tests! The reason is that these tests cannot run inside a container
# because the pid of the test executable doesn't match the pid outside the container. We use this docker image
# just to check that the modern probe is correctly loaded.
CMD ["/usr/local/bin/bpf_test", "--gtest_filter='NO_TEST'"]
