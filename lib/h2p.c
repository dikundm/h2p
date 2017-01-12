/*
 * h2p - HTTP/2 Parsing Library
 */
#include <h2p/h2p.h>

//#include "nghttp2/nghttp2.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>

#define H2P_DEBUG printf("h2p: %s\n", __FUNCTION__);
#define LOG_AND_RETURN(m, r) { printf("h2p: %s\n", m); return r; } 

#define H2P_INIT_SERVER 1
#define H2P_INIT_CLIENT (!H2P_INIT_SERVER)

void deflate(nghttp2_hd_deflater *deflater,
             nghttp2_hd_inflater *inflater, const nghttp2_nv *const nva,
             size_t nvlen);

int inflate_header_block(nghttp2_hd_inflater *inflater, uint8_t *in,
                         size_t inlen, int final);


void stream_destroy(h2p_stream *stream) {
  if (!stream) return;

  free(stream->data);
  free(stream);
}

int on_begin_frame_callback(nghttp2_session *session,
                            const nghttp2_frame_hd *hd,
                            void *user_data) {
  h2p_context *context = (h2p_context*)user_data;
  h2p_frame_type frame_type;
  int32_t stream_id;

  H2P_DEBUG

  context->last_frame_type = hd->type;
  context->last_stream_id = hd->stream_id;

  //context->callbacks->h2_frame(context, last_stream_id, last_frame_type, NULL);

  return 0;
}

int on_begin_headers_callback(nghttp2_session *session _U_,
                              const nghttp2_frame *frame,
                              void *user_data) {
  h2p_context *context = (h2p_context*)user_data;
  h2p_stream *stream;
  khiter_t iter;
  int not_found = 0, push_ret = 0;
  int32_t stream_id = frame->hd.stream_id;

  H2P_DEBUG

  if (frame->hd.type != NGHTTP2_HEADERS) {
    //context->last_frame_type = -1;
    //context->last_stream_id = -1;
    return 0;
  }
  
  iter = kh_get(h2_streams_ht, context->streams, stream_id);
  not_found = (iter == kh_end(context->streams));

  if (not_found) {

    // !

    stream = malloc (sizeof(h2p_stream));
    memset(stream, 0, sizeof(h2p_stream));
    iter = kh_put(h2_streams_ht, context->streams, stream_id, &push_ret);
    kh_value(context->streams, iter) = stream;
  } else {
    stream = kh_value(context->streams, iter);
    if (stream->id != stream_id) {
      LOG_AND_RETURN("ERROR: Stream table corrupted!\n", -1)
    }
  }

  if (stream->headers == NULL && stream->headers_num != 0) {
    stream->headers = malloc (sizeof(nghttp2_nv));
    stream->headers_num = 0;
  } else {
    printf ("ERROR: HEADERS frame recursion!\n");
    return 0;
  }

  return 0;
}

int on_header_callback(nghttp2_session *session _U_,
                       const nghttp2_frame *frame, const uint8_t *name,
                       size_t namelen, const uint8_t *value,
                       size_t valuelen, uint8_t flags _U_,
                       void *user_data) {
  h2p_context *context = (h2p_context*)user_data;
  h2p_stream *stream;
  khiter_t iter;
  int not_found = 0, push_ret = 0;
  int32_t stream_id = frame->hd.stream_id;

  H2P_DEBUG

  iter = kh_get(h2_streams_ht, context->streams, stream_id);
  not_found = (iter == kh_end(context->streams));

  if (not_found) {
    LOG_AND_RETURN("ERROR: Stream table corrupted!\n", -1)
  }

  stream = kh_value(context->streams, iter);

  if (stream->headers_num > 0) {
    stream->headers = realloc(stream->headers, (stream->headers_num + 1)
                              * sizeof(nghttp2_nv));
  }

  stream->headers[stream->headers_num].name = malloc(namelen);
  memcpy(stream->headers[stream->headers_num].name,
         name, namelen);
  stream->headers[stream->headers_num].namelen = namelen;

  stream->headers[stream->headers_num].value = malloc(valuelen);
  memcpy(stream->headers[stream->headers_num].value,
         value, valuelen);
  stream->headers[stream->headers_num].valuelen = valuelen;

  stream->headers[stream->headers_num].flags = flags;

  stream->headers_num++;

  return 0;
}

int on_frame_recv_callback(nghttp2_session *session _U_,
                           const nghttp2_frame *frame, void *user_data) {
  h2p_context *context = (h2p_context*)user_data;
  nghttp2_frame_hd *hd = (nghttp2_frame_hd *)frame;

  H2P_DEBUG

  if (context->last_stream_id != -1 && context->last_frame_type != -1) {
    
    context->callbacks->h2_frame(context,
                                context->last_stream_id,
                                context->last_frame_type,
                                frame);

    if (context->last_frame_type != hd->type || 
        context->last_stream_id != hd->stream_id) {

      context->callbacks->h2_frame(context,
                                hd->stream_id,
                                hd->type,
                                frame);
    }
  }

  context->last_stream_id = -1;
  context->last_frame_type = -1;

  return 0;
}

int on_data_chunk_recv_callback(nghttp2_session *session _U_,
                                uint8_t flags _U_, int32_t stream_id,
                                const uint8_t *data, size_t len,
                                void *user_data) {
  h2p_context *context = (h2p_context*)user_data;
  h2p_frame_data stream_data;
  h2p_stream *stream;
  khiter_t iter;
  int not_found = 0, push_ret = 0;

  H2P_DEBUG
  
  iter = kh_get(h2_streams_ht, context->streams, stream_id);
  not_found = (iter == kh_end(context->streams));

  if (not_found) {
    stream = malloc (sizeof(h2p_stream));
    iter = kh_put(h2_streams_ht, context->streams, stream_id, &push_ret);
    kh_value(context->streams, iter) = stream;

    stream->id = stream_id;
    stream->data = malloc (len);
    memcpy(stream->data, data, len);
    stream->size = len;
    stream->need_decode = 0;

    if (context->callbacks->h2_data_started(context, stream->id)) {
      stream->need_decode = 1;
    }

    context->callbacks->h2_data(context, stream->id,
                                (h2p_frame_data *)stream);

  } else {
    stream = kh_value(context->streams, iter);
    if (stream->id != stream_id) {
      LOG_AND_RETURN("ERROR: Stream table corrupted!\n", -1)
    }

    stream->data = realloc(stream->data, len + stream->size);
    memcpy(stream->data + stream->size, data, len);
    stream->size += len;

    stream_data.data = data;
    stream_data.size = len;

    context->callbacks->h2_data(context, stream->id, &stream_data);
  }

  return 0;
}

int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                             uint32_t error_code, void *user_data) {
  h2p_context *context = (h2p_context*)user_data;
  h2p_stream *stream;
  khiter_t iter;
  int not_found = 0;
  
  H2P_DEBUG
  
  iter = kh_get(h2_streams_ht, context->streams, stream_id);
  not_found = (iter == kh_end(context->streams));

  if (not_found) {
    LOG_AND_RETURN("ERROR: Stream table corrupted!\n", -1)
  } else {
    stream = kh_value(context->streams, iter);

    if (stream->id != stream_id) {
      stream_destroy (stream);
      kh_del(h2_streams_ht, context->streams, iter);
      LOG_AND_RETURN("ERROR: Stream table corrupted!\n", -1)
    }

    if (stream->need_decode) {
      // DEFLATE(...)
      ;
    }

    // RST_STREAM 
  }

  stream_destroy (stream);
  kh_del(h2_streams_ht, context->streams, iter);
  return 0;
}

#if 0

int on_invalid_header_callback(
    nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name,
    size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags,
    void *user_data) {
  h2p_context *context = (h2p_context*)user_data;

  H2P_DEBUG
  return 0;
}

int on_invalid_frame_recv_callback(nghttp2_session *session,
                                   const nghttp2_frame *frame,
                                   int lib_error_code, 
                                   void *user_data) {
  h2p_context *context = (h2p_context*)user_data;

  H2P_DEBUG
  return 0;
}

#endif

int error_callback(nghttp2_session *session, const char *msg,
                   size_t len, void *user_data) {
  H2P_DEBUG;
  printf ("%s", msg);
  return 0;
}


int h2p_init(h2p_callbacks *callbacks, h2p_direction direction,
             h2p_context **connection) {
  int                         status = 0;
  nghttp2_session             *ngh2_session;
  nghttp2_session_callbacks   *ngh2_callbacks;

  *connection = malloc (sizeof(h2p_context));
  (*connection)->callbacks = callbacks;
  status = nghttp2_session_callbacks_new(&ngh2_callbacks);

  // recv 
  //nghttp2_session_callbacks_set_recv_callback(ngh2_callbacks, recv_callback);

  // begin frame
  nghttp2_session_callbacks_set_on_begin_frame_callback(ngh2_callbacks,
                                                       on_begin_frame_callback);

  // frame recv
  nghttp2_session_callbacks_set_on_frame_recv_callback (
    ngh2_callbacks, on_frame_recv_callback);

  // invalid frame recv
#if 0
  nghttp2_session_callbacks_set_on_invalid_frame_recv_callback (
    ngh2_callbacks, on_invalid_frame_recv_callback);
#endif

  // data chunck recv
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
    ngh2_callbacks, on_data_chunk_recv_callback);

  // stream close
  nghttp2_session_callbacks_set_on_stream_close_callback(
    ngh2_callbacks, on_stream_close_callback);

  // header
  nghttp2_session_callbacks_set_on_header_callback(ngh2_callbacks,
                                                   on_header_callback);

  // begin headers
  nghttp2_session_callbacks_set_on_begin_headers_callback(ngh2_callbacks,
                                                     on_begin_headers_callback);

  // error
  nghttp2_session_callbacks_set_error_callback (ngh2_callbacks, error_callback);

  if (direction) {
    status = nghttp2_session_server_new(&ngh2_session, ngh2_callbacks, *connection);
  } else {
    status = nghttp2_session_server_new(&ngh2_session, ngh2_callbacks, *connection);
  }

  (*connection)->session = ngh2_session;
  //(*connection)->ngh2_callbacks = ngh2_callbacks;
  
  nghttp2_session_callbacks_del (ngh2_callbacks);

  (*connection)->streams = kh_init(h2_streams_ht);

  return status;
}


int h2p_input(h2p_context *connection, h2p_direction direction, 
              unsigned char *buffer, size_t len) {
  int nbytes;

  if (connection == NULL || buffer == NULL || len == 0) return -1;

  if (nghttp2_session_want_read(connection->session) == 0) 
    LOG_AND_RETURN("nghttp2_session_want_read = 0", -1)

  nbytes = nghttp2_session_mem_recv (connection->session, buffer, len);
  //s = nghttp2_session_send (connection->ngh2_session);

  if (nbytes < 0) printf("ERROR: %s.\n", nghttp2_strerror(nbytes));

  return 0;
}


int h2p_free(h2p_context *context)  {
  khiter_t iter;

  if (context == NULL) return -1;

  for (iter = kh_begin(context->streams); iter != kh_end(context->streams); ++iter) {
    if (kh_exist(context->streams, iter)) {
      stream_destroy (kh_value(context->streams, iter));
     // kh_del(h2_streams_ht, context->streams, iter);
    }
  }

  kh_destroy(h2_streams_ht, context->streams);
  nghttp2_session_del(context->session);

  free(context);

  return 0;
}

// 
void deflate(nghttp2_hd_deflater *deflater,
                    nghttp2_hd_inflater *inflater, const nghttp2_nv *const nva,
                    size_t nvlen) {
  ssize_t rv;
  uint8_t *buf;
  size_t buflen, outlen, i, sum;

  sum = 0;

  for (i = 0; i < nvlen; ++i) {
    sum += nva[i].namelen + nva[i].valuelen;
  }

  buflen = nghttp2_hd_deflate_bound(deflater, nva, nvlen);
  buf = malloc(buflen);

  rv = nghttp2_hd_deflate_hd(deflater, buf, buflen, nva, nvlen);

  if (rv < 0) {
    printf("ERROR: %s.\n", nghttp2_strerror(rv));
    free(buf);
    return;
  }

  outlen = (size_t)rv;
  /* We pass 1 to final parameter, because buf contains whole deflated
     header data. */
  rv = inflate_header_block(inflater, buf, outlen, 1);

  free(buf);
}

int inflate_header_block(nghttp2_hd_inflater *inflater, uint8_t *in,
                         size_t inlen, int final) {
  ssize_t rv;

  for (;;) {
    nghttp2_nv nv;
    int inflate_flags = 0;
    size_t proclen;

    rv = nghttp2_hd_inflate_hd(inflater, &nv, &inflate_flags, in, inlen, final);

    if (rv < 0) {
      return -1;
    }

    proclen = (size_t)rv;
    in += proclen;
    inlen -= proclen;

    if (inflate_flags & NGHTTP2_HD_INFLATE_FINAL) {
      nghttp2_hd_inflate_end_headers(inflater);
      break;
    }

    if ((inflate_flags & NGHTTP2_HD_INFLATE_EMIT) == 0 && inlen == 0) {
      break;
    }
  }

  return 0;
}