#include "uv_tls.h"

uv_stream_t *uv_tls_get_stream(uv_tls_t *tls) {
    return (uv_stream_t *) &tls->socket_;
}

int uv_tls_init(uv_loop_t *loop, uv_tls_t *strm) {
    uv_tcp_init(loop, &strm->socket_);
    strm->socket_.data = strm;

    tls_engine *ng = &(strm->tls_eng);
    tls_engine_init(ng);

    ng->ssl_bio_ = 0;
    ng->app_bio_ = 0;
    strm->oprn_state = STATE_INIT;
    strm->rd_cb = NULL;
    strm->close_cb = NULL;
    strm->on_tls_connect = NULL;
    return 0;
}

void stay_uptodate(uv_tls_t *sec_strm, uv_alloc_cb uv__tls_alloc) {
    uv_stream_t * client = uv_tls_get_stream(sec_strm);

    size_t pending = BIO_ctrl_pending(sec_strm->tls_eng.app_bio_);
    if( pending > 0) {

        //Need to free the memory
        uv_buf_t mybuf;

        if(uv__tls_alloc) {
            uv__tls_alloc((uv_handle_t*)client, (size_t)pending, &mybuf);
        }

        int rv = BIO_read(sec_strm->tls_eng.app_bio_, mybuf.base, pending);
        assert( rv == pending );

        rv = uv_try_write(client, &mybuf, 1);
        assert(rv == pending);

        free(mybuf.base);
        mybuf.base = 0;
    }
}

static void uv__tls_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    buf->base = malloc(size);
    assert(buf->base != NULL && "Memory allocation failed");
    buf->len = size;
}

//handle only non fatal error currently
int uv__tls_err_hdlr(uv_tls_t *k, const int err_code) {
    switch(err_code) {
        case MBEDTLS_ERR_SSL_WANT_WRITE:
        case MBEDTLS_ERR_SSL_WANT_READ: {
            stay_uptodate(k, uv__tls_alloc);
            break;
        }
        case OK: {
            return OK;
        }
        default: {
            char buf[512];
            mbedtls_strerror(err_code, buf, 512);
            __log(0, "uv__tls_err_hdlr error:%s\n", buf);
            return err_code;
        }
    }
    return err_code;
}

void after_close(uv_handle_t *hdl) {
    uv_tls_t *s = CONTAINER_OF((uv_tcp_t*)hdl, uv_tls_t, socket_);
    if( s->close_cb) {
        s->close_cb(s);
        s = NULL;
    }
}

int uv__tls_close(uv_tls_t *session) {

    tls_engine *tls = &(session->tls_eng);

    if (tls->app_bio_) {
        BIO_free_all(tls->app_bio_);
    }
    if (tls->ssl_bio_) {
        BIO_free_all(tls->ssl_bio_);
    }

//    int rv = SSL_shutdown(ng->ssl);
//    int ssl_error;
//    uv__tls_err_hdlr(session, rv);
//
//    if( rv == 0) {
//        session->oprn_state = STATE_CLOSING;
//        rv = SSL_shutdown(ng->ssl);
//        uv__tls_err_hdlr(session, rv);
//    }
//
//    if( rv == 1) {

//    }
//
//    BIO_free(ng->app_bio_);
//    ng->app_bio_ = NULL;
//    SSL_free(ng->ssl);
//    ng->ssl = NULL;
//
//    uv_close( (uv_handle_t*)uv_tls_get_stream(session), after_close);
//
//    return rv;
    session->oprn_state = STATE_CLOSING;
    uv_close( (uv_handle_t*)uv_tls_get_stream(session), after_close);
    return 0;
}

//shutdown the ssl session then stream
int uv_tls_close(uv_tls_t *session, tls_close_cb cb) {
    session->close_cb = cb;
    return uv__tls_close(session);
}

int uv__tls_handshake(uv_tls_t *tls) {
    if( tls->oprn_state & STATE_IO) {
        return 1;
    }
    int rv = 0, ssl_error;
    rv = mbedtls_ssl_handshake(&tls->tls_eng.ssl);
    rv = uv__tls_err_hdlr(tls, rv);

    tls->oprn_state = STATE_HANDSHAKING;

    if(rv == 0) {
        tls->oprn_state = STATE_IO;
        int status = mbedtls_ssl_get_verify_result(&tls->tls_eng.ssl);

        if (status) {
            char vrfy_buf[512];

            mbedtls_printf( " failed\n" );

            mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", status );

            mbedtls_printf( "%s\n", vrfy_buf );
        }


        if(tls->on_tls_connect) {
            assert(tls->con_req);
            tls->on_tls_connect(tls->con_req, status);
        }
    }
    return 0;
}

int uv_tls_shutdown(uv_tls_t *session) {
//    assert( session != NULL && "Invalid session");
//
//    SSL_CTX_free(session->tls_eng.ctx);
//    session->tls_eng.ctx = NULL;

    return 0;
}

uv_buf_t encode_data(uv_tls_t *sessn, uv_buf_t *data2encode) {
    //this should give me something to write to client
    size_t rv = (size_t)mbedtls_ssl_write(&sessn->tls_eng.ssl,(const unsigned char *) data2encode->base, data2encode->len);

    size_t pending = 0;
    uv_buf_t encoded_data = {.base = 0, .len = 0};
    if( (pending = BIO_ctrl_pending(sessn->tls_eng.app_bio_) ) > 0 ) {

        encoded_data.base = (char*)malloc(pending);
        encoded_data.len = pending;

        rv = BIO_read(sessn->tls_eng.app_bio_, encoded_data.base, pending);
        data2encode->len = rv;
    }
    return encoded_data;
}

int uv_tls_write(uv_write_t *req,
                 uv_tls_t *client,
                 uv_buf_t *buf,
                 uv_write_cb on_tls_write) {

    const uv_buf_t data = encode_data(client, buf);

    int rv = uv_write(req, uv_tls_get_stream(client), &data, 1, on_tls_write);
    if (data.base != NULL) {
        free(data.base);
    }
    return rv;
}

size_t uv__tls_read(uv_tls_t *tls, uv_buf_t *dcrypted, int sz) {

    if( 1 != uv__tls_handshake(tls)) {
        //recheck if handshake is complete now
        return STATE_HANDSHAKING;
    }
//
//    //clean the slate
    memset( dcrypted->base, 0, sz);
    int rv = mbedtls_ssl_read(&tls->tls_eng.ssl, (unsigned char *)dcrypted->base, sz);
    uv__tls_err_hdlr(tls, rv);

    dcrypted->len = (size_t) rv;
    if( tls->rd_cb) {
        tls->rd_cb(tls, rv, dcrypted);
    }
    return rv;
}

void on_tcp_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {

    uv_tls_t *parent = CONTAINER_OF(client, uv_tls_t, socket_);
    assert( parent != NULL);

    if( nread <= 0
    // ( parent->oprn_state & STATE_IO)
    ) {
        printf("on_tcp_read error: %s\n", uv_strerror(nread));
        if (parent->rd_cb) parent->rd_cb(parent, nread, (uv_buf_t*)buf);
    } else {
        BIO_write( parent->tls_eng.app_bio_, buf->base, nread);
        uv__tls_read(parent, (uv_buf_t*)buf, nread);
    }
    free(buf->base);
}

//uv_alloc_cb is unused, but here for cosmetic reasons
//Need improvement
int uv_tls_read(uv_tls_t *sclient, tls_rd_cb on_read) {
    sclient->rd_cb = on_read;
    return 0;
}


void on_tcp_conn(uv_connect_t *c, int status) {
    uv_tls_t *sclnt = c->handle->data;
    assert(sclnt != 0);

    if (status < 0) {
        sclnt->on_tls_connect(c, status);
    } else { //tcp connection established
        uv__tls_handshake(sclnt);
        uv_read_start((uv_stream_t *) &sclnt->socket_, uv__tls_alloc, on_tcp_read);
    }
}

static int assume_role(tls_engine *tls) {
    mbedtls_ssl_context ctx = tls->ssl;

//    tls_ngin->ssl = SSL_new(tls_ngin->ctx);
//    if(!tls_ngin->ssl) {
//        return ERR_TLS_ERROR;
//    }
//
//    if( endpt_role == 1) {
//        SSL_set_accept_state(tls_ngin->ssl);
//    }
//    else {
//        //set in client mode
//        SSL_set_connect_state(tls_ngin->ssl);
//    }
//
//    //use default buf size for now.
//    if( !BIO_new_bio_pair(&(tls_ngin->ssl_bio_), 0, &(tls_ngin->app_bio_), 0)) {
//        return ERR_TLS_ERROR;
//    }
//    SSL_set_bio(tls_ngin->ssl, tls_ngin->ssl_bio_, tls_ngin->ssl_bio_);
    int ret;
    mbedtls_printf("  . Setting up the SSL/TLS structure...\n");

    if ((ret = mbedtls_ssl_config_defaults(&tls->conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
    }

    mbedtls_printf(" ok\n");

    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&tls->conf, &tls->cacert, NULL);
    mbedtls_ssl_conf_rng(&tls->conf, mbedtls_ctr_drbg_random, &tls->ctr_drbg);
//    mbedtls_ssl_conf_dbg( &tls->conf, my_debug, stdout );

    if ((ret = mbedtls_ssl_setup(&tls->ssl, &tls->conf)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n", ret);
        return ERR_TLS_ERROR;
    }


    tls->ssl_bio_ = SSL_BIO_new(BIO_BIO);
    tls->app_bio_ = SSL_BIO_new(BIO_BIO);
    BIO_make_bio_pair(tls->ssl_bio_, tls->app_bio_);

//    mbedtls_ssl_set_bio( &tls->ssl, tls->ssl_bio_, mbedtls_net_send, mbedtls_net_recv, NULL );
    mbedtls_ssl_set_bio(&tls->ssl, tls->ssl_bio_, BIO_net_send, BIO_net_recv, NULL);
    return ERR_TLS_OK;
}


int uv_tls_connect(
        uv_connect_t *req,
        uv_tls_t *hdl,
        const char *host,
        int port,
        uv_connect_cb cb) {

    tls_engine *tls_ngin = &(hdl->tls_eng);
    int rv = assume_role(tls_ngin);
//
    if( ( rv = mbedtls_ssl_set_hostname( &tls_ngin->ssl, host) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", rv );
        rv = ERR_TLS_ERROR;
    }

    struct sockaddr_in addr_in;
    struct addrinfo *req_addr;

    int ret = getaddrinfo(host, NULL, NULL, &req_addr);
    if (ret) {
        __log(LOG_VERBOSE, "get address info error");
        return -1;
    }

    memcpy(&addr_in, req_addr->ai_addr, sizeof(struct sockaddr_in));
    addr_in.sin_port = htons(port);

    freeaddrinfo(req_addr);


    if (rv != ERR_TLS_OK) {
        return rv;
    }

    hdl->on_tls_connect = cb;
    hdl->con_req = req;

    return uv_tcp_connect(req, &(hdl->socket_), (const struct sockaddr *)&addr_in, on_tcp_conn);
}


