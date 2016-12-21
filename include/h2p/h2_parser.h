/*
 *  HTTP2 parser API.
 */
#ifndef H2_PARSER_H
#define H2_PARSER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

int h2_parser_connect(long id, parser_callbacks *callbacks, connection_context **p_context);
int h2_parser_disconnect(connection_context *context, enum transfer_direction direction);
int h2_parser_input(connection_context *context, enum transfer_direction direction, char *buffer, int length);
int h2_parser_close(connection_context *context);

/*  enum h2_frame_type
 */
typedef enum {
  NGHTTP2_DATA = 0,
  NGHTTP2_HEADERS = 0x01,
  NGHTTP2_PRIORITY = 0x02,
  NGHTTP2_RST_STREAM = 0x03,
  NGHTTP2_SETTINGS = 0x04,
  NGHTTP2_PUSH_PROMISE = 0x05,
  NGHTTP2_PING = 0x06,
  NGHTTP2_GOAWAY = 0x07,
  NGHTTP2_WINDOW_UPDATE = 0x08,
  /**
   * The CONTINUATION frame.  This frame type won't be passed to any
   * callbacks because the library processes this frame type and its
   * preceding HEADERS/PUSH_PROMISE as a single frame.
   */
  NGHTTP2_CONTINUATION = 0x09,
  /**
   * The ALTSVC frame, which is defined in `RFC 7383
   * <https://tools.ietf.org/html/rfc7838#section-4>`_.
   */
  NGHTTP2_ALTSVC = 0x0a
} h2_frame_type;

typedef struct {
    void (*h2_frame)(connection_context *context, unsigned int stream_id, 
                     enum h2_frame_type type, struct frame_any frame);
    void (*h2_headers)(connection_context *context, unsigned int stream_id,
                       struct frame_headers headers);
    void (*h2_data_started)(connection_context *context,
                            unsigned int stream_id);
    void (*h2_data)(connection_context *context, unsigned int stream_id,
                    struct frame_data data);
};

#ifdef __cplusplus
}
#endif

#endif /* H2_PARSER_H */