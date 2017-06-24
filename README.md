# What is this
Port [mbedTLS](https://github.com/ARMmbed/mbedtls) on libuv, based on BIO which refers to [wolfSSL/src/bio.c](https://github.com/wolfSSL/wolfssl/blob/master/src/bio.c) and the project is inspired by [libuv-tls](https://github.com/deleisha/libuv-tls)

ses API in uv_tls.c.
just use

0. `uv_tls_init` for `uv_tcp_init`
0. `uv_tls_connect` for `uv_tcp_connect`
0. `uv_tls_read` for `uv_read_start`
0. `uv_tls_write` for `uv_write`

# TODO
add a fully example.