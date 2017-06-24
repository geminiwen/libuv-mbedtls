//
// Created by Gemini on 2017/6/23.
//

#ifndef CHAT_BIO_H
#define CHAT_BIO_H

#include "strings.h"
#include "stdlib.h"
#include "mbedtls/ssl.h"
#include "ssl.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char BYTE;

struct _BIO;
typedef struct _BIO BIO;

struct _BIO {
    BIO* prev;          /* previous in chain */
    BIO* next;          /* next in chain */
    BIO* pair;          /* BIO paired with */
    BYTE*        mem;           /* memory buffer */
    int          wrSz;          /* write buffer size (mem) */
    int          wrIdx;         /* current index for write buffer */
    int          rdIdx;         /* current read index */
    int          readRq;        /* read request */
    int          memLen;        /* memory buffer length */
    int          type;          /* method type */
};

enum {
    SSL_BIO_ERROR = -1,
    SSL_BIO_UNSET = -2,
    SSL_BIO_SIZE  = 17000 /* default BIO write size if not set */
};

enum BIO_TYPE {
    BIO_BUFFER = 1,
    BIO_SOCKET = 2,
    BIO_SSL    = 3,
    BIO_MEMORY = 4,
    BIO_BIO    = 5,
    BIO_FILE   = 6
};


// 抽象 IO API

BIO *SSL_BIO_new(int type);
int BIO_make_bio_pair(BIO *b1, BIO *b2);


size_t BIO_ctrl_pending(BIO *bio);
int BIO_read(BIO *bio, const char *buf, size_t size);
int BIO_write(BIO *bio, const char *buf, size_t size);

int BIO_net_recv( void *ctx, unsigned char *buf, size_t len);
int BIO_net_send( void *ctx, const unsigned char *buf, size_t len );
int BIO_free_all(BIO* bio);
int BIO_free(BIO* bio);

#ifdef __cplusplus
};
#endif

#endif //CHAT_BIO_H
