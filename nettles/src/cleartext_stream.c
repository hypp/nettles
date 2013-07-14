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
#include <assert.h>

#include "stream_internal.h"
#include "cleartext_stream.h"

error_type_t stream_read_cleartext(stream_handle_t stream, struct evbuffer* buffer)
{
	int ret = bufferevent_read_buffer(stream->bev, buffer);
	if (ret == 0)
	{
		return ERROR_OK;
	}
	else
	{
		return ERROR_FAILED;
	}
}

error_type_t stream_write_cleartext(stream_handle_t stream, struct evbuffer* buffer)
{
	int ret = bufferevent_write_buffer(stream->bev, buffer);
	if (ret == 0)
	{
		return ERROR_OK;
	}
	else
	{
		return ERROR_FAILED;
	}
}

void stream_connected_cleartext(stream_handle_t stream)
{
	assert(stream != NULL);

	// Nothing to do...
}

void stream_disconnect_cleartext(stream_handle_t stream)
{
	assert(stream != NULL);

	// Disconnect underlying socket
	stream_close(stream);
}

void stream_free_cleartext(stream_handle_t stream)
{
	if (stream != NULL)
	{
		stream->ref_count--;

		if (stream->ref_count > 0)
		{
			return;
		}

		if (stream->bev != NULL)
		{
			bufferevent_free(stream->bev);
			stream->bev = NULL;
		}

		stream_release_other(stream);

		// Clear it to catch possible use after free
		memset(stream,0,sizeof(struct stream));
		free(stream);
	}
}

stream_handle_t stream_new_cleartext()
{
	stream_handle_t stream = malloc(sizeof(struct stream));
	if (stream != NULL)
	{
		memset(stream,0,sizeof(struct stream));
		stream->ref_count++;

		stream->read = stream_read_cleartext;
		stream->write = stream_write_cleartext;
		stream->free = stream_free_cleartext;
		stream->connected = stream_connected_cleartext;
		stream->disconnect = stream_disconnect_cleartext;
	}
	return stream;
}

