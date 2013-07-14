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

#ifndef STREAM_H_
#define STREAM_H_

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/util.h>
#include <event2/dns.h>

// This is the main interface for a stream
// It is implemented as PIMPL and just forwards all calls to the implementation
// Currently there are two implementations, cleartext_stream and ssl_stream

typedef enum {
	STATE_INIT,
	STATE_CONNECTING,
	STATE_CONNECTED,
	STATE_HANDSHAKE,
	STATE_AUTHENTICATED,
	STATE_CLOSING,
	STATE_CLOSED
} state_type_t;

typedef enum {
	ERROR_OK,
	ERROR_FAILED
} error_type_t;

typedef struct stream* stream_handle_t;


//stream_handle_t stream_new();

// Free this stream, if refcount <= 0
void stream_free(stream_handle_t stream);

// Add a reference to this stream
void stream_add_ref(stream_handle_t stream);

// Connect this stream to another stream
void stream_add_other(stream_handle_t stream, stream_handle_t other);
// Get the other stream
stream_handle_t stream_get_other(stream_handle_t stream);
// Release the other stream
void stream_release_other(stream_handle_t stream);

// Get the current state of this stream
state_type_t stream_get_state(stream_handle_t stream);
// Set the current state of this stream
void stream_set_state(stream_handle_t stream, state_type_t state);

// Get the underlying libevent bufferevent
struct bufferevent* stream_get_bev(stream_handle_t stream);
// Set the underlying libevent bufferevent
void stream_set_bev(stream_handle_t stream, struct bufferevent* bev);

// Notify the stream that it is connected
void stream_connected(stream_handle_t stream);
// Check if the stream is connected
int stream_is_connected(stream_handle_t stream);

// Disconnect the stream
void stream_disconnect(stream_handle_t stream);

// Disable the stream
void stream_disable(stream_handle_t stream);
// Enable the stream
void stream_enable(stream_handle_t stream);

// Read data from the stream
error_type_t stream_read(stream_handle_t stream, struct evbuffer* buffer);
// Write data to the stream
error_type_t stream_write(stream_handle_t stream, struct evbuffer* buffer);

#endif /* STREAM_H_ */
