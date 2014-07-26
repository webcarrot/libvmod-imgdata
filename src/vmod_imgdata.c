/*
        Copyright (C) 2014 Wojciech Wierchola <admin@webcarrot.eu>
        Copyright (C) 2013 Aivars Kalvans <aivars.kalvans@gmail.com>

        This program is free software; you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published
        by the Free Software Foundation; either version 3 of the License,
        or (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
        General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program; if not, see <http://www.gnu.org/licenses>.

        Additional permission under GNU GPL version 3 section 7

        If you modify this Program, or any covered work, by linking or
        combining it with libvmod-example (or a modified version of that
        library), containing parts covered by the terms of Aivars Kalvans
        the licensors of this Program grant you additional permission to
        convey the resulting work. {Corresponding Source for a non-source
        form of such a combination shall include the source code for the
        parts of libvmod-example used as well as that of the covered work.}
*/

#include <stdio.h>
#include <stdlib.h>
#include <regex.h>


#include "vrt.h"
#include "vqueue.h"
#include "vsha256.h"
#include "bin/varnishd/cache.h"
#include "bin/varnishd/stevedore.h"
#include "vcc_if.h"

// CURL
#include <curl/curl.h>
#include <curl/easy.h>

// BASE 64
#include <stddef.h>
#include <stdbool.h>
# define BASE64_LENGTH(inlen) ((((inlen) + 2) / 3) * 4)
#include <limits.h>
#include <string.h>


void vmod_imgdata_base64_encode ( const char *in, size_t inlen,
                                  char *out, size_t outlen );
size_t vmod_imgdata_base64_encode_alloc ( const char *in, size_t inlen, char **out );

int init_function ( struct vmod_priv *priv, const struct VCL_conf *conf )
{
    return 0;
}

struct buf_t {
    char *ptr;
    size_t len;
    size_t size;
};

#define BUF_GROW(buf) do { \
        (buf)->ptr = realloc((buf)->ptr, (buf)->size); \
        AN((buf)->ptr); \
} while (0)

#define BUF_RESERVE(buf, n) while ((buf)->size <= (buf)->len + (n)) { \
                (buf)->size *= 2; \
                if(  (buf)->size > (buf)->len + (n) ) { \
                        BUF_GROW(buf); \
                        break; \
                } \
        } \
 
/*
static size_t write_to_base64 ( void *ptr, size_t size, size_t nmemb, void *userp )
{
    struct buf_t *mem = ( struct buf_t * ) userp;

    char *base64_out;
    size_t base64_out_len = vmod_imgdata_base64_encode_alloc ( ptr, size * nmemb, &base64_out );

    while ( mem->len + base64_out_len > mem->size ) {
        mem->size *= 2;
        mem->ptr = realloc ( mem->ptr, mem->size );
    }

    memcpy ( & ( mem->ptr[mem->len] ), base64_out, base64_out_len );
    mem->len += base64_out_len;

    return size * nmemb;
}
*/

static size_t write_to_buf ( void *ptr, size_t size, size_t nmemb, void *userp )
{
    struct buf_t *mem = ( struct buf_t * ) userp;
    size_t length = size * nmemb / sizeof ( char );

    BUF_RESERVE ( mem, length );

    memcpy ( & ( mem->ptr[mem->len] ), ptr, length );
    mem->len += length;

    return size * nmemb;
}

static struct buf_t _object_read ( struct sess *sp )
{
    struct storage *st;
    size_t len;
    struct buf_t buf = {NULL, 0, 1024 * 1024};

    BUF_GROW ( &buf );
    CHECK_OBJ_NOTNULL ( sp, SESS_MAGIC );

    if ( !sp->obj->gziped ) {

        VTAILQ_FOREACH ( st, &sp->obj->store, list ) {
            CHECK_OBJ_NOTNULL ( sp, SESS_MAGIC );
            CHECK_OBJ_NOTNULL ( st, STORAGE_MAGIC );

            BUF_RESERVE ( &buf, st->len );
            memcpy ( buf.ptr + buf.len, st->ptr, st->len );
            buf.len += st->len;
        }
    } else {
        struct vgz *vg;
        char obuf[params->gzip_stack_buffer];
        ssize_t obufl = 0;
        const void *dp;
        size_t dl;

        vg = VGZ_NewUngzip ( sp, "U D -" );

        VTAILQ_FOREACH ( st, &sp->obj->store, list ) {
            CHECK_OBJ_NOTNULL ( sp, SESS_MAGIC );
            CHECK_OBJ_NOTNULL ( st, STORAGE_MAGIC );

            BUF_RESERVE ( &buf, st->len * 2 );
            VGZ_Ibuf ( vg, st->ptr, st->len );
            do {
                VGZ_Obuf ( vg, buf.ptr + buf.len, buf.size - buf.len );
                if ( buf.len < buf.size ) {
                    VGZ_Gunzip ( vg, &dp, &dl );
                    buf.len += dl;
                } else {
                    BUF_RESERVE ( &buf, st->len );
                }
            } while ( !VGZ_IbufEmpty ( vg ) );
        }
        VGZ_Destroy ( &vg );
    }
    BUF_RESERVE ( &buf, 1 );
    buf.ptr[buf.len] = '\0';
    return buf;
}

static void _object_write ( struct sess *sp, struct buf_t * buf )
{
    struct vsb *vsb;
    char *header;

    sp->wrk->is_gzip = 0;
    sp->wrk->is_gunzip = 1;
    /* FIXME: add gzip support */
    sp->wrk->do_gzip = 0;
    sp->wrk->do_gunzip = 0;

    CHECK_OBJ_NOTNULL ( sp, SESS_MAGIC );
    CHECK_OBJ_NOTNULL ( sp->obj, OBJECT_MAGIC );
    vsb = SMS_Makesynth ( sp->obj );
    AN ( vsb );
    VSB_bcpy ( vsb, buf->ptr, buf->len );
    SMS_Finish ( sp->obj );

    sp->obj->gziped = 0;
    sp->wrk->res_mode = 0;
    sp->wrk->res_mode |= RES_LEN;



    /* Header must outlive our plugin */
    http_Unset ( sp->obj->http, H_Content_Length );
    http_Unset ( sp->wrk->resp, H_Content_Length );
    http_Unset ( sp->obj->http, H_Content_Encoding );
    http_Unset ( sp->wrk->resp, H_Content_Encoding );
    http_Unset ( sp->obj->http, H_Transfer_Encoding );
    http_Unset ( sp->wrk->resp, H_Transfer_Encoding );
    http_PrintfHeader ( sp->wrk, sp->fd, sp->obj->http, "Content-Length: %jd", ( intmax_t ) sp->obj->len );
    http_PrintfHeader ( sp->wrk, sp->fd, sp->wrk->resp, "Content-Length: %jd", ( intmax_t ) sp->obj->len );
}

static int _object_imgdata ( struct buf_t *buf, regex_t *re_search )
{
    CURL *curl;
    CURLcode res;
    int rewrote = 0;
    char *base64_out;
    size_t base64_out_len;

    curl_global_init ( CURL_GLOBAL_DEFAULT );

    curl = curl_easy_init();
    if ( curl ) {

        size_t buf_pos;
        struct buf_t replacement = {NULL, 0, 1024 * 32};
        struct buf_t url = {NULL, 0, 1024};
        struct buf_t img_data = {NULL, 0, 1024 * 32};

        curl_easy_setopt ( curl, CURLOPT_SSL_VERIFYPEER, 0L );
        curl_easy_setopt ( curl, CURLOPT_SSL_VERIFYHOST, 0L );
        curl_easy_setopt ( curl, CURLOPT_WRITEFUNCTION, write_to_buf );
        curl_easy_setopt ( curl, CURLOPT_WRITEDATA, ( void * ) &img_data );
        curl_easy_setopt ( curl, CURLOPT_USERAGENT, "vmod-imgdata/0.1" );
        curl_easy_setopt ( curl, CURLOPT_NOSIGNAL , 1L );
        curl_easy_setopt ( curl, CURLOPT_NOPROGRESS, 1L );
        curl_easy_setopt ( curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1 );

        void *headers=NULL;
        headers = curl_slist_append ( headers, "Connection: Keep-Alive" );
        headers = curl_slist_append ( headers, "Keep-Alive: 300" );

        curl_easy_setopt ( curl, CURLOPT_HTTPHEADER, headers );

        regmatch_t pmatch[10];
        char file_ext = 'j';
        char file_data_text[23];

        /* Temporary buffer for creating replacement string */
        BUF_GROW ( &replacement );

        /* Temporary buffer for creating url string */
        BUF_GROW ( &url );

        /* Temporary buffer for creating url string */
        BUF_GROW ( &img_data );

        buf_pos = 0;
        while ( buf_pos < buf->len && regexec ( re_search, buf->ptr + buf_pos,
                                                sizeof ( pmatch ) / sizeof ( pmatch[0] ), pmatch, 0 ) == 0 ) {

            int so, n, diff;

            replacement.len = 0;
            url.len = 0;
            img_data.len = 0;

            // full url
            so = pmatch[0].rm_so;
            n = pmatch[0].rm_eo - so;
            BUF_RESERVE ( &url, n );
            memcpy ( url.ptr + url.len, buf->ptr + buf_pos + so, n );
            url.len = n;
            // type (jpg|jpeg|png|gif)
            so = pmatch[1].rm_so;
            file_ext = * ( buf->ptr + buf_pos + so );


            // CURL request
            curl_easy_setopt ( curl, CURLOPT_URL, url.ptr );

            res = curl_easy_perform ( curl );
            if ( res == CURLE_OK ) {
                base64_out_len = vmod_imgdata_base64_encode_alloc ( img_data.ptr, img_data.len, &base64_out );
                if(base64_out_len > 2)
                {
                    // replacement data:image/xxx;base64,
                    switch ( file_ext ) {
                    case 'p':
                        strcpy ( file_data_text, "data:image/png;base64," );
                        break;
                    case 'g':
                        strcpy ( file_data_text, "data:image/gif;base64," );
                        break;
                    case 'j':
                        strcpy ( file_data_text, "data:image/jpg;base64," );
                        break;
                    }
                    memcpy ( replacement.ptr, file_data_text, 22 );
                    replacement.len += 22;
                    // replacement base64
                    BUF_RESERVE ( &replacement, base64_out_len );
                    memcpy ( replacement.ptr + replacement.len, base64_out, base64_out_len );
                    replacement.len += base64_out_len;
                    free ( base64_out );
                }
                else
                {
                    replacement.len = 0;
                }
            } else {
                replacement.len = 0;
            }
            if ( replacement.len > 0 ) {
                // Insert replacement string into document
                rewrote = 1;
                diff = replacement.len - ( pmatch[0].rm_eo - pmatch[0].rm_so );
                BUF_RESERVE ( buf, diff );

                memmove ( buf->ptr + ( buf_pos + pmatch[0].rm_so + replacement.len ),
                          buf->ptr + ( buf_pos + pmatch[0].rm_eo ),
                          buf->len - ( buf_pos + pmatch[0].rm_eo ) );
                memcpy ( buf->ptr + ( buf_pos + pmatch[0].rm_so ), replacement.ptr, replacement.len );
                buf->len += diff;
                // Advance position inside document so we don't process the same data again and again
                BUF_RESERVE ( buf,1 );
                buf->ptr[buf->len-1] = '\0';
                buf_pos += diff;
            }
            buf_pos += pmatch[0].rm_eo;
        }
        free ( replacement.ptr );
        free ( url.ptr );
        free ( img_data.ptr );
        curl_easy_cleanup ( curl );
    }
    return rewrote;
}

void vmod_imgdata_re ( struct sess *sp, const char *postfix )
{
    struct buf_t buf;

    if ( sp->step != STP_PREPRESP ) {
        /* Can be called only from vcl_deliver */
        abort();
        return;
    }

    /* object from cache, rewritten before */
    if ( sp->obj->hits > 0 ) {
        return;
    }
    
    regex_t re_search;
    const char *prefix = "https?://[^\"' ]+\\.(jpg|jpeg|png|gif)";
    char *search;
    unsigned int length = 0;
    if( strlen(postfix) > 0 )
    {
        length = strlen(prefix) + strlen(postfix);
        search = malloc ( ( length + 1  ) * sizeof(char) );
	search[0] = '\0';
        strcat (search, prefix);
        strcat (search, postfix);
        search[ length ] = '\0';
    }
    else
    {
        length = strlen(prefix);
        search = malloc ( ( length + 1  ) * sizeof(char) );
	search[0] = '\0';
        strcat (search, prefix);
        search[ length ] = '\0';
    }


    if ( regcomp ( &re_search, search, REG_EXTENDED ) != 0 ) {
        free(search);
        abort();
        return;
    }


    buf = _object_read ( sp );

    if ( _object_imgdata ( &buf, &re_search ) ) {
        _object_write ( sp, &buf );
    }
    
    free(search);

    regfree ( &re_search );
}


/* base64.c -- Encode binary data using printable characters.
   Copyright (C) 1999-2001, 2004-2006, 2009-2013 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.  */

/* Written by Simon Josefsson.  Partially adapted from GNU MailUtils
 * (mailbox/filter_trans.c, as of 2004-11-28).  Improved by review
 * from Paul Eggert, Bruno Haible, and Stepan Kasal.
 *
 * See also RFC 4648 <http://www.ietf.org/rfc/rfc4648.txt>.
 *
 * Be careful with error checking.  Here is how you would typically
 * use these functions:
 *
 * bool ok = base64_decode_alloc (in, inlen, &out, &outlen);
 * if (!ok)
 *   FAIL: input was not valid base64
 * if (out == NULL)
 *   FAIL: memory allocation error
 * OK: data in OUT/OUTLEN
 *
 * size_t outlen = vmod_imgdata_base64_encode_alloc (in, inlen, &out);
 * if (out == NULL && outlen == 0 && inlen != 0)
 *   FAIL: input too long
 * if (out == NULL)
 *   FAIL: memory allocation error
 * OK: data in OUT/OUTLEN.
 *
 */


/* C89 compliant way to cast 'char' to 'unsigned char'. */
static unsigned char
vmod_imgdata_to_uchar ( char ch )
{
    return ch;
}

static const char vmod_imgdata_b64c[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Base64 encode IN array of size INLEN into OUT array. OUT needs
   to be of length >= BASE64_LENGTH(INLEN), and INLEN needs to be
   a multiple of 3.  */
static void
vmod_imgdata_base64_encode_fast ( const char *in, size_t inlen, char *out )
{
    while ( inlen ) {
        *out++ = vmod_imgdata_b64c[vmod_imgdata_to_uchar ( in[0] ) >> 2];
        *out++ = vmod_imgdata_b64c[ ( ( vmod_imgdata_to_uchar ( in[0] ) << 4 ) + ( vmod_imgdata_to_uchar ( in[1] ) >> 4 ) ) & 0x3f];
        *out++ = vmod_imgdata_b64c[ ( ( vmod_imgdata_to_uchar ( in[1] ) << 2 ) + ( vmod_imgdata_to_uchar ( in[2] ) >> 6 ) ) & 0x3f];
        *out++ = vmod_imgdata_b64c[vmod_imgdata_to_uchar ( in[2] ) & 0x3f];

        inlen -= 3;
        in += 3;
    }
}

/* Base64 encode IN array of size INLEN into OUT array of size OUTLEN.
   If OUTLEN is less than BASE64_LENGTH(INLEN), write as many bytes as
   possible.  If OUTLEN is larger than BASE64_LENGTH(INLEN), also zero
   terminate the output buffer. */
void
vmod_imgdata_base64_encode ( const char *in, size_t inlen,
                             char *out, size_t outlen )
{
    /* Note this outlen constraint can be enforced at compile time.
       I.E. that the output buffer is exactly large enough to hold
       the encoded inlen bytes.  The inlen constraints (of corresponding
       to outlen, and being a multiple of 3) can change at runtime
       at the end of input.  However the common case when reading
       large inputs is to have both constraints satisfied, so we depend
       on both in base_encode_fast().  */
    if ( outlen % 4 == 0 && inlen == outlen / 4 * 3 ) {
        vmod_imgdata_base64_encode_fast ( in, inlen, out );
        return;
    }

    while ( inlen && outlen ) {
        *out++ = vmod_imgdata_b64c[vmod_imgdata_to_uchar ( in[0] ) >> 2];
        if ( !--outlen )
            break;
        *out++ = vmod_imgdata_b64c[ ( ( vmod_imgdata_to_uchar ( in[0] ) << 4 )
                                      + ( --inlen ? vmod_imgdata_to_uchar ( in[1] ) >> 4 : 0 ) )
                                    & 0x3f];
        if ( !--outlen )
            break;
        *out++ =
            ( inlen
              ? vmod_imgdata_b64c[ ( ( vmod_imgdata_to_uchar ( in[1] ) << 2 )
                                     + ( --inlen ? vmod_imgdata_to_uchar ( in[2] ) >> 6 : 0 ) )
                                   & 0x3f]
      : '=' );
        if ( !--outlen )
            break;
        *out++ = inlen ? vmod_imgdata_b64c[vmod_imgdata_to_uchar ( in[2] ) & 0x3f] : '=';
        if ( !--outlen )
            break;
        if ( inlen )
            inlen--;
        if ( inlen )
            in += 3;
    }

    if ( outlen )
        *out = '\0';
}

/* Allocate a buffer and store zero terminated base64 encoded data
   from array IN of size INLEN, returning BASE64_LENGTH(INLEN), i.e.,
   the length of the encoded data, excluding the terminating zero.  On
   return, the OUT variable will hold a pointer to newly allocated
   memory that must be deallocated by the caller.  If output string
   length would overflow, 0 is returned and OUT is set to NULL.  If
   memory allocation failed, OUT is set to NULL, and the return value
   indicates length of the requested memory block, i.e.,
   BASE64_LENGTH(inlen) + 1. */
size_t
vmod_imgdata_base64_encode_alloc ( const char *in, size_t inlen, char **out )
{
    size_t outlen = 1 + BASE64_LENGTH ( inlen );

    /* Check for overflow in outlen computation.
     *
     * If there is no overflow, outlen >= inlen.
     *
     * If the operation (inlen + 2) overflows then it yields at most +1, so
     * outlen is 0.
     *
     * If the multiplication overflows, we lose at least half of the
     * correct value, so the result is < ((inlen + 2) / 3) * 2, which is
     * less than (inlen + 2) * 0.66667, which is less than inlen as soon as
     * (inlen > 4).
     */
    if ( inlen > outlen ) {
        *out = NULL;
        return 0;
    }

    *out = malloc ( outlen );
    if ( !*out )
        return outlen;

    vmod_imgdata_base64_encode ( in, inlen, *out, outlen );

    return outlen - 1;
}
