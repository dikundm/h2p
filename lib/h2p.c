/*
 * h2p - HTTP/2 Parsing Library
 */
#include <h2p/h2p.h>

//#include "nghttp2/nghttp2.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define H2P_DEBUG printf("h2p: %s\n", __FUNCTION__);
#define LOG_AND_RETURN(m, r) { printf("h2p: %s\nReturn from %s.\n", m,\
                              __FUNCTION__); return r; } 

#define H2P_INIT_SERVER 1
#define H2P_INIT_CLIENT (!H2P_INIT_SERVER)

#define STREAM_ID_OFFSET 5

void stream_destroy(h2p_stream *stream) {
  if (!stream) return;

  if (stream->headers != NULL) {
    if (stream->headers->nvlen != 0) {
      free(stream->headers->nva);
    }
    free(stream->headers);
  }

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
  h2p_frame_data stream_data;
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

  iter = kh_get(h2_streams_ht, context->streams, frame->hd.stream_id);
  not_found = (iter == kh_end(context->streams));

  if (not_found) {
    //LOG_AND_RETURN("ERROR: Stream table corrupted!\n", -1)
    stream = malloc (sizeof(h2p_stream));
    memset(stream, 0, sizeof(h2p_stream));

    iter = kh_put(h2_streams_ht, context->streams, stream_id, &push_ret);
    kh_value(context->streams, iter) = stream;

    stream->id = stream_id;
  } else {
    stream = kh_value(context->streams, iter);
  }

  if (stream->headers != NULL) {
    if (stream->headers->nvlen != 0) {
      free(stream->headers->nva);
    }
    free(stream->headers);
  }

  stream->headers = malloc (sizeof(nghttp2_headers));
  memcpy(stream->headers, frame, sizeof(nghttp2_headers));

  stream->headers->nva = malloc(stream->headers->nvlen *
                                 sizeof(nghttp2_nv));
  stream->nvlen = 0;

  return 0;
}

int on_header_callback(nghttp2_session *session _U_,
                       const nghttp2_frame *frame, const uint8_t *name,
                       size_t namelen, const uint8_t *value,
                       size_t valuelen, uint8_t flags _U_,
                       void *user_data) {
  h2p_context *context = (h2p_context*)user_data;
  h2p_frame_data stream_data;
  h2p_stream *stream;
  khiter_t iter;
  int not_found = 0, push_ret = 0;

  H2P_DEBUG

  iter = kh_get(h2_streams_ht, context->streams, frame->hd.stream_id);
  not_found = (iter == kh_end(context->streams));

  if (not_found) {
    LOG_AND_RETURN("ERROR: Stream table corrupted!\n", -1)
  } else {
    stream = kh_value(context->streams, iter);
  }

  if (stream->headers == NULL) {
    H2P_DEBUG ("WARNING: Memory for header was not allocated!\n");
  }

  stream->headers->nva[stream->nvlen].name = malloc (namelen);
  memcpy(stream->headers->nva[stream->nvlen].name, name, namelen);
  stream->headers->nva[stream->nvlen].namelen = namelen;

  stream->headers->nva[stream->nvlen].value = malloc (valuelen);
  memcpy(stream->headers->nva[stream->nvlen].value, value, valuelen);
  stream->headers->nva[stream->nvlen].valuelen = valuelen;

  stream->headers->nva[stream->nvlen].flags = flags;

  stream->nvlen++;

  printf ("%ld %ld\n", stream->nvlen, stream->headers->nvlen);

  if (stream->nvlen == stream->headers->nvlen) {
    context->callbacks->h2_headers(context, stream->headers->hd.stream_id,
                                   stream->headers);
    if (stream->headers != NULL) {
      if (stream->headers->nvlen != 0) {
        free(stream->headers->nva);
      }
      free(stream->headers);
    }
  }

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

  context->callbacks->h2_data_finished(context, stream_id, error_code);

  stream_destroy (stream);
  kh_del(h2_streams_ht, context->streams, iter);
  return 0;
}

#if 1

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

  printf ("INVALID FRAME : %d\n",lib_error_code);

  //context->callbacks->h2_error(context, H2P_ERROR_INVALID_FRAME, nghttp2_error_code);
  return 0;
}

#endif

int error_callback(nghttp2_session *session, const char *msg,
                   size_t len, void *user_data) {
  h2p_context *context = (h2p_context*)user_data;
  
  H2P_DEBUG;
  
  context->callbacks->h2_error(context, H2P_ERROR_MESSAGE, msg);
  return 0;
}

ssize_t send_callback(nghttp2_session *session _U_, const uint8_t *data,
                             size_t length, int flags _U_, void *user_data) {
  H2P_DEBUG
  return length;
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
#if 1
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

  nghttp2_session_callbacks_set_send_callback (ngh2_callbacks, send_callback);

  if (direction) {
    status = nghttp2_session_server_new(&ngh2_session, ngh2_callbacks, *connection);
  } else {
    status = nghttp2_session_client_new(&ngh2_session, ngh2_callbacks, *connection);
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


  if (nghttp2_session_want_write(connection->session))
    nghttp2_session_send(connection->session);

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

#if 0
  if (context->headers != NULL) {
    if (context->headers->nvlen != 0) {
      free(context->headers->nva);
    }
    free(context->headers);
  }
#endif

  free(context);

  return 0;
}

typedef struct {
  uint8_t       *data;
  size_t        len;
  unsigned int  iteration;
} util_return_data;

ssize_t _util_send_callback(nghttp2_session *session _U_, const uint8_t *data,
                             size_t length, int flags _U_, void *user_data) {
  util_return_data *rd = (util_return_data *)user_data;

  // Skip 24 bytes client magic.
  if (rd->iteration == 1) {

    rd->len = length;
    rd->data = malloc (length);
    memcpy (rd->data, data, length);

  } else if (rd->iteration > 1) {

    rd->data = realloc (rd->data, rd->len + length);
    memcpy (rd->data + rd->len, data, length);
    rd->len += length;
  }

  rd->iteration++;

  return (ssize_t)length;
}

uint8_t *h2p_raw_settings(nghttp2_settings_entry *iv, int iv_num,
                          size_t *len) {
  nghttp2_session             *session;
  nghttp2_session_callbacks   *callbacks;
  util_return_data            return_data = {0,0,0};
  int status;

  nghttp2_session_callbacks_new(&callbacks);
  nghttp2_session_callbacks_set_send_callback(callbacks, _util_send_callback);
  nghttp2_session_client_new(&session, callbacks, &return_data);
  nghttp2_session_callbacks_del(callbacks);

  status = nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv,
                                  iv_num);

  if (status != 0) return NULL;

  nghttp2_session_send(session);

  nghttp2_session_del(session);
  
  *len = return_data.len;
  return return_data.data;
}

uint8_t *h2p_raw_headers(int32_t stream_id, nghttp2_nv *headers, 
                         int headers_num, size_t *len) {
  nghttp2_session             *session;
  nghttp2_session_callbacks   *callbacks;
  util_return_data            return_data = {0,0,0};

  nghttp2_session_callbacks_new(&callbacks);
  nghttp2_session_callbacks_set_send_callback(callbacks, _util_send_callback);
  nghttp2_session_client_new(&session, callbacks, &return_data);
  nghttp2_session_callbacks_del(callbacks);

  nghttp2_submit_headers(session, NGHTTP2_FLAG_NONE, -1, NULL,
                              headers, headers_num, NULL);

  nghttp2_session_send(session);

  *(int32_t*)&(return_data.data[STREAM_ID_OFFSET]) = htonl(stream_id);

  nghttp2_session_del(session);
  
  *len = return_data.len;
  return return_data.data;
}

typedef struct {
  uint8_t *data;
  size_t  len;
  size_t  offset;
} util_data_source;

#define MIN(x,y) (x < y ? x : y)
#define MAX(x,y) (x > y ? x : y)

ssize_t _util_read_callback(nghttp2_session *session _U_,
                            int32_t stream_id _U_, uint8_t *buf,
                            size_t length, uint32_t *data_flags,
                            nghttp2_data_source *source,
                            void *user_data _U_) {
  //H2P_DEBUG

  util_data_source *ds = source->ptr;
  ssize_t nbytes;

  nbytes = MIN(ds->len - ds->offset, length);

  if (nbytes == 0) return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;

  memcpy(buf, ds->data + ds->offset, nbytes);

  ds->offset += nbytes;

  if (ds->offset == ds->len) {
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  }

  return nbytes;
}

uint8_t *h2p_raw_data(int32_t stream_id, uint8_t *data, size_t data_size,
                      size_t *len) {

  nghttp2_session             *session;
  nghttp2_session_callbacks   *callbacks;
  util_return_data            return_data = {0,0,0};
  int                         rv;
  nghttp2_data_provider       data_prd;
  util_data_source            data_source;
  int32_t                     sid;

  data_source.data = data;
  data_source.len = data_size;
  data_source.offset = 0;

  data_prd.source.ptr = &data_source;
  data_prd.read_callback = _util_read_callback;

  nghttp2_session_callbacks_new(&callbacks);
  nghttp2_session_callbacks_set_send_callback(callbacks, _util_send_callback);
  nghttp2_session_client_new(&session, callbacks, &return_data);
  nghttp2_session_callbacks_del(callbacks);

  nghttp2_nv hdrs;

  sid = nghttp2_submit_headers(session, NGHTTP2_FLAG_NONE, -1, NULL,
                               &hdrs, 0, NULL);

  nghttp2_session_send(session);

  if (return_data.data != NULL) free(return_data.data);
  return_data.data = NULL;
  return_data.len = 0;
  return_data.iteration = 1;

  rv = nghttp2_submit_data(session, NGHTTP2_FLAG_NONE, sid, &data_prd);
  if (rv != 0) {
    printf("Fatal error: %s", nghttp2_strerror(rv));
    return NULL;
  }

  nghttp2_session_send(session);

  *(int32_t*)&(return_data.data[STREAM_ID_OFFSET]) = htonl(stream_id);

  nghttp2_session_del(session);
  
  *len = return_data.len;
  return return_data.data;
}