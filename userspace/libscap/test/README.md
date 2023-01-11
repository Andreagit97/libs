# Scap tests

## Compile tests

```bash
cmake -DUSE_BUNDLED_DEPS=On -DBUILD_BPF=Off -DBUILD_DRIVER=Off -DCREATE_TEST_TARGETS=On -DBUILD_LIBSCAP_GVISOR=Off ..
make unit-test-libscap
```

You can add tests for specific engines using their Cmake options:
- `-DBUILD_LIBSCAP_MODERN_BPF=On`
- `-DBUILD_LIBSCAP_GVISOR=On`
- `-DBUILD_BPF=ON` (this will require `make bpf` before running tests)
- `-DBUILD_DRIVER=ON` (this will require `make driver` before running tests)

## Run tests

From the build directory:

```bash
sudo ./libscap/test/unit-test-libscap
```
