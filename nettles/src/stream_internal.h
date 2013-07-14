/*
   Copyright 2012 Mathias Olsson

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#ifndef STREAM_INTERNAL_H_
#define STREAM_INTERNAL_H_

#include "stream.h"

// These are the internal functions of the stream interface which should be implemented
// by the actual streams

typedef error_type_t (*stream_read_func_t)(stream_handle_t stream, struct evbuffer* buffer);
typedef error_type_t (*stream_write_func_t)(stream_handle_t stream, struct evbuffer* buffer);
typedef void (*stream_connected_func_t)(stream_handle_t stream);
typedef void (*stream_disconnect_func_t)(stream_handle_t stream);
typedef void (*stream_free_func_t)(stream_handle_t stream);

struct stream {
	int ref_count;

	struct bufferevent *bev;

	state_type_t state;
    struct stream* other;

	stream_free_func_t free;
	stream_connected_func_t connected;
	stream_disconnect_func_t disconnect;
	stream_read_func_t read;
	stream_read_func_t write;

	void* internal_data;
};

stream_handle_t stream_new();
void stream_close(stream_handle_t stream);

#endif /* STREAM_INTERNAL_H_ */
