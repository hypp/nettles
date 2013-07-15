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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "stream_internal.h"

stream_handle_t stream_new()
{
	stream_handle_t stream = malloc(sizeof(struct stream));
	if (stream != NULL)
	{
		memset(stream,0,sizeof(struct stream));
		stream->ref_count++;
	}
	return stream;
}

void stream_close(stream_handle_t stream)
{
	assert(stream != NULL);

	stream->state = STATE_CLOSED;
	if (stream->bev != NULL)
	{
		bufferevent_flush(stream->bev, EV_READ | EV_WRITE, BEV_FINISHED);
		bufferevent_free(stream->bev);
	}
	stream->bev = NULL;
}


void stream_free(stream_handle_t stream)
{
	if (stream != NULL)
	{
		stream->free(stream);
	}
}

void stream_add_ref(stream_handle_t stream)
{
	if (stream != NULL)
	{
		stream->ref_count++;
	}
}


int stream_is_connected(stream_handle_t stream)
{
	assert(stream != NULL);

	return stream->state != STATE_CLOSED;
}

void stream_add_other(stream_handle_t stream, stream_handle_t other)
{
	assert(stream != NULL);

	stream_free(stream->other);
	stream_add_ref(other);
	stream->other = other;
}

stream_handle_t stream_get_other(stream_handle_t stream)
{
	assert(stream != NULL);

	return stream->other;
}

void stream_release_other(stream_handle_t stream)
{
	assert(stream != NULL);

	stream_add_other(stream,NULL);
}

void stream_disconnect(stream_handle_t stream)
{
	assert(stream != NULL);

	stream->disconnect(stream);
}

error_type_t stream_read(stream_handle_t stream, struct evbuffer* buffer)
{
	assert(stream != NULL);
	assert(stream_is_connected(stream));

	int ret = ERROR_FAILED;

	ret = stream->read(stream, buffer);

	return ret;
}

error_type_t stream_write(stream_handle_t stream, struct evbuffer* buffer)
{
	assert(stream != NULL);
	assert(stream_is_connected(stream));

	int ret = ERROR_FAILED;

	ret = stream->write(stream, buffer);

	return ret;
}

state_type_t stream_get_state(stream_handle_t stream)
{
	assert(stream != NULL);

	return stream->state;
}

void stream_set_state(stream_handle_t stream, state_type_t state)
{
	assert(stream != NULL);

	stream->state = state;
}

void stream_connected(stream_handle_t stream)
{
	assert(stream != NULL);

	stream->state = STATE_CONNECTED;
	stream->connected(stream);
}

struct bufferevent* stream_get_bev(stream_handle_t stream)
{
	assert(stream != NULL);

	return stream->bev;
}

void stream_set_bev(stream_handle_t stream, struct bufferevent* bev)
{
	assert(stream != NULL);

	if (stream->bev != NULL)
	{
		bufferevent_free(stream->bev);
		stream->bev = NULL;
	}

	stream->bev = bev;
}
