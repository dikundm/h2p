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
 * The frame types in HTTP/2 specification.
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

typedef struct h2p_context h2p_context;

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
                   h2p_frame_type type, h2p_frame frame);

  /**
   * @funcmember h2_headers
   *
   * @context     - h2p_context object;
   * @stream_id   - actual HTTP2 stream ID;
   * @headers     - headers frame (after un-HPACK);
   */
  void (*h2_headers)(h2p_context *context, uint32_t stream_id,
                     h2p_frame headers);

  /**
   * @funcmember h2_data_started
   *
   * @context     - h2p_context object;
   * @stream_id   - actual HTTP2 stream ID;
   */
  void (*h2_data_started)(h2p_context *context, uint32_t stream_id);

  /**
   * @funcmember h2_data
   *
   * @context     - h2p_context object;
   * @stream_id   - actual HTTP2 stream ID;
   * @data        - data frame;
   */
  void (*h2_data)(h2p_context *context, uint32_t stream_id,
                  h2p_frame data);

  /**
   * @funcmember h2_data_finished
   *
   * @context     - h2p_context object;
   * @stream_id   - actual HTTP2 stream ID;
   * @rst_stream  - H2P_END_STREAM when stream is finished, or 
   *                is reset if H2P_RST_STREAM.
   */
  void (*h2_data_finished)(h2p_context *context, uint32_t stream_id,
                           h2p_frame data);
} h2p_callbacks;

struct h2p_context {
    h2p_callbacks         *callbacks;
    nghttp2_session       *session;
    nghttp2_hd_deflater   *deflater;
    nghttp2_hd_inflater   *inflater;
};

/*
 * General parser interface:
 */
int h2p_init(h2p_callbacks *callbacks, /*h2p_direction direction,*/ h2p_context **context);
int h2p_input(h2p_context *context, /* h2p_direction direction, */ unsigned char *buffer, size_t len);
int h2p_free(h2p_context *context);

/* Next #ifndef ... #endif section's stuff is grabbed from nghttp2 library.
 */


#ifdef __cplusplus
}
#endif

#endif /* H2P_H */