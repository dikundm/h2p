/*
 * h2p - HTTP/2 Parsing Library
 */
#ifndef H2P_H
#define H2P_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h> /* uint32_t for HTTP2 stream ID. */
#include <sys/types.h> /* size_t where it is needed. */

#include "nghttp2/nghttp2.h"

#include "khash.h"

#define h2p_frame nghttp2_frame

/**
 * @enum h2p_direction
 *
 */
typedef enum {
    H2P_DIRECTION_IN = 0,
    H2P_DIRECTION_OUT
} h2p_direction;

/**
 * The frame types from HTTP/2 specification.
 */
typedef enum {
  H2P_FRAME_TYPE_DATA           = 0,
  H2P_FRAME_TYPE_HEADERS        = 0x01,
  H2P_FRAME_TYPE_PRIORITY       = 0x02,
  H2P_FRAME_TYPE_RST_STREAM     = 0x03,
  H2P_FRAME_TYPE_SETTINGS       = 0x04,
  H2P_FRAME_TYPE_PUSH_PROMISE   = 0x05,
  H2P_FRAME_TYPE_PING           = 0x06,
  H2P_FRAME_TYPE_GOAWAY         = 0x07,
  H2P_FRAME_TYPE_WINDOW_UPDATE  = 0x08,
  H2P_FRAME_TYPE_CONTINUATION   = 0x09,
  H2P_FRAME_TYPE_ALTSVC         = 0x0a
} h2p_frame_type;

/**
 * Errors
 */
typedef enum {
  H2P_ERROR_INVALID_HEADER  = 1,
  H2P_ERROR_INVALID_FRAME,
  H2P_ERROR_MESSAGE
} h2p_error_type;

typedef struct h2p_context h2p_context;

typedef struct h2p_frame_data h2p_frame_data;

/**
 * @struct h2p_callbacks
 *
 * Parser callbacks.
 */
typedef struct {

  /**
   * @funcmember h2_frame
   *
   * @context     - h2p_context object;
   * @stream_id   - actual HTTP2 stream ID;
   * @frame       - frame to be send;
   * @user_data   - attach for this session;
   */
  void (*h2_frame)(h2p_context *context, uint32_t stream_id,
                   h2p_frame_type type, const h2p_frame *frame);

  /**
   * @funcmember h2_headers
   *
   * @context     - h2p_context object;
   * @stream_id   - actual HTTP2 stream ID;
   * @headers     - headers frame (after un-HPACK);
   */
  void (*h2_headers)(h2p_context *context, uint32_t stream_id,
                     const nghttp2_headers *headers);

  /**
   * @funcmember h2_data_started
   *
   * @context     - h2p_context object;
   * @stream_id   - actual HTTP2 stream ID;
   */
  int (*h2_data_started)(h2p_context *context, uint32_t stream_id);

  /**
   * @funcmember h2_data
   *
   * @context     - h2p_context object;
   * @stream_id   - actual HTTP2 stream ID;
   * @data        - data frame;
   */
  void (*h2_data)(h2p_context *context, uint32_t stream_id,
                  const h2p_frame_data *data);

  /**
   * @funcmember h2_data_finished
   *
   * @context     - h2p_context object;
   * @stream_id   - actual HTTP2 stream ID;
   * @data        - data frame;
   * @rst_stream  - H2P_END_STREAM when stream is finished, or 
   *                is reset if H2P_RST_STREAM.
   */
  void (*h2_data_finished)(h2p_context *context, uint32_t stream_id,
                           uint32_t status);

  /**
   * @funcmember h2_error
   *
   * @context     - h2p_context object;
   * @type        - error type;
   * @msg         - error message;
   */
  void (*h2_error)(h2p_context *context, h2p_error_type type, const char *msg);
} h2p_callbacks;

struct h2p_frame_data
{
  const uint8_t *data; /* Not 0-terminated C-string! You must to use .size! */
  size_t        size;
};

typedef struct 
{
  uint8_t           *data; /* Not 0-terminated C-string! */
  size_t            size;
  uint32_t          id;
  uint8_t           need_decode; /* Just 0 or 1 if need or not to decode. */
  nghttp2_headers   *headers;
  size_t            nvlen;
} h2p_stream;

KHASH_MAP_INIT_INT(h2_streams_ht, h2p_stream*)

struct h2p_context {
  h2p_callbacks           *callbacks;
  nghttp2_session         *session;
  khash_t(h2_streams_ht)  *streams;
  h2p_frame_type          last_frame_type;
  int32_t                 last_stream_id;
};

/*
 * General parser interface:
 */
int h2p_init(h2p_callbacks *callbacks, h2p_direction direction,
             h2p_context **context);
int h2p_input(h2p_context *context, h2p_direction direction,
              unsigned char *buffer, size_t len);
int h2p_free(h2p_context *context);


#define H2_MAGIC "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

uint8_t *h2p_raw_settings(nghttp2_settings_entry *iv, int iv_num,
                          size_t *len);

#define MAKE_NV_3(NAME, VALUE, VALUELEN)                                       \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, VALUELEN,             \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

#define MAKE_NV_2(NAME, VALUE)                                                 \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,    \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

uint8_t *h2p_raw_headers(int32_t stream_id, nghttp2_nv *headers,
                         int headers_num, size_t *len);
uint8_t *h2p_raw_data(int32_t stream_id, uint8_t *data, size_t data_size,
                      size_t *len);

/* Next #ifndef ... #endif section's stuff is grabbed from nghttp2 library.
 */


#ifdef __cplusplus
}
#endif

#endif /* H2P_H */