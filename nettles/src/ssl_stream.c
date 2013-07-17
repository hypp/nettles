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

#include "ssl_stream.h"


int tls_net_recv(void *user_data, unsigned char *buffer, size_t len)
{
	stream_handle_t stream  = user_data;

	struct evbuffer *input = bufferevent_get_input(stream->bev);
	if (input == NULL)
	{
		goto error;
	}

	int ret = evbuffer_remove(input,buffer,len);
	if (ret <= 0)
	{
		return( POLARSSL_ERR_NET_WANT_READ );
	}
	else
	{
		return ret;
	}

error:
	return( POLARSSL_ERR_NET_RECV_FAILED );
}

int tls_net_send(void *user_data, const unsigned char *buffer, size_t len)
{
	stream_handle_t stream = user_data;

	struct evbuffer *output = bufferevent_get_output(stream->bev);
	if (output == NULL)
	{
		goto error;
	}

	int ret = evbuffer_add(output,buffer,len);
	if (ret < 0)
	{
		return( POLARSSL_ERR_NET_WANT_WRITE );
	}
	else
	{
		ret = bufferevent_write_buffer(stream->bev, output);
		if (ret != 0)
		{
			// Handle error
			return( POLARSSL_ERR_NET_SEND_FAILED );
		}
		else
		{
			return len;
		}
	}

error:
	return( POLARSSL_ERR_NET_SEND_FAILED );
}

error_type_t stream_read_ciphertext(stream_handle_t stream, struct evbuffer* buffer)
{
	struct cipher_context* context = stream->internal_data;
	state_type_t state = stream->state;

	if (stream->state == STATE_CLOSING) {
		// Got data while closing

		// Error! Disconnect
		stream_disconnect(stream);
		return ERROR_FAILED;
	}

	if (state == STATE_HANDSHAKE)
	{
		int ret = ssl_handshake(&context->ssl);
		if (ret == 0)
		{
			int ret = ssl_get_verify_result(&context->ssl);
			if (ret != 0)
			{
				// Error! Disconnect
				stream_disconnect(stream);
				return ERROR_FAILED;
			}
			else
			{
				stream->state = STATE_AUTHENTICATED;

				if (context->authentication_cb != NULL)
				{
					context->authentication_cb(stream,context->authentication_cb_data);
				}

				// Fall through
			}
		}
		else if (ret == POLARSSL_ERR_NET_WANT_READ)
		{
			return ERROR_OK;
		}
		else if (ret == POLARSSL_ERR_NET_WANT_WRITE)
		{
			return ERROR_OK;
		}
		else
		{
			// Error! Disconnect
			stream_disconnect(stream);
			return ERROR_FAILED;
		}
	}

	// No else

	if (state == STATE_AUTHENTICATED)
	{
		int ret = 0;
		do
		{
			// TODO Optimize this!!!
#define READ_BUFFER_LEN 4096
			unsigned char buf[READ_BUFFER_LEN];
			size_t len = READ_BUFFER_LEN;
			ret = ssl_read(&context->ssl, buf, len );
			if (ret > 0)
			{
				int res = evbuffer_add(buffer,buf,ret);
				if (res != 0)
				{
					// Handle error
					return ERROR_FAILED;
				}
			}
			else if (ret == POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY)
			{
				stream->state = STATE_CLOSING;
				stream_disconnect(stream);

				return ERROR_FAILED;
			}
			else if (ret == POLARSSL_ERR_NET_WANT_READ)
			{
				return ERROR_OK;
			}
			else if (ret == POLARSSL_ERR_NET_WANT_WRITE)
			{
				return ERROR_OK;
			}
			else
			{
				// Unhandled error...
				return ERROR_FAILED;
			}
		} while (ret > 0);

	}

	return ERROR_OK;
}

error_type_t stream_write_ciphertext(stream_handle_t stream, struct evbuffer* buffer)
{
	size_t len = evbuffer_get_length(buffer);
	if (len > 0)
	{
		unsigned char* buf = evbuffer_pullup(buffer,len);
		if (buf == NULL)
		{
			return ERROR_FAILED;
		}
		else
		{
			struct cipher_context* context = stream->internal_data;
			int ret = ssl_write(&context->ssl, buf, len );
			if (ret > 0)
			{
				evbuffer_drain(buffer,ret);
			}
			else if (ret == POLARSSL_ERR_NET_WANT_READ)
			{
//				int x = 42;
			}
			else if (ret == POLARSSL_ERR_NET_WANT_WRITE)
			{
//				int x = 42;
			}
			else
			{
				// TODO Handle error, this should never happen...
				return ERROR_FAILED;
			}
		}
	}
	else
	{
		return ERROR_FAILED;
	}

	return ERROR_OK;
}

void stream_connected_ciphertext(stream_handle_t stream)
{
	assert(stream != NULL);

	bufferevent_enable(stream->bev, EV_WRITE | EV_READ);

	stream->state = STATE_HANDSHAKE;
	struct cipher_context* context = stream->internal_data;
	(void)ssl_handshake(&context->ssl);
}

void stream_disconnect_ciphertext(stream_handle_t stream)
{
	assert(stream != NULL);

	if (stream->state == STATE_CLOSED)
	{
		return;
	}

	if (stream->state == STATE_CLOSING)
	{
		// Disconnect underlying socket
		stream_close(stream);
	}
	else
	{
		// Tell other end that we are shutting down
		stream->state = STATE_CLOSING;
		struct cipher_context* context = stream->internal_data;
		(void)ssl_close_notify(&context->ssl);
	}
}

void stream_free_ciphertext(stream_handle_t stream)
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

		struct cipher_context* context = stream->internal_data;
		ssl_free(&context->ssl);
		x509_free(&context->ca);
		x509_crl_free(&context->crl);
		x509_free(&context->certificate);
		rsa_free(&context->rsa);

		free(context);

		// Clear it to catch possible use after free
		memset(stream,0,sizeof(struct stream));
		free(stream);
	}
}

stream_handle_t stream_new_ssl()
{
	stream_handle_t stream = stream_new();
	if (stream != NULL)
	{
		stream->read = stream_read_ciphertext;
		stream->write = stream_write_ciphertext;
		stream->free = stream_free_ciphertext;
		stream->connected = stream_connected_ciphertext;
		stream->disconnect = stream_disconnect_ciphertext;

		stream->internal_data = malloc(sizeof(struct cipher_context));
		if (stream->internal_data == NULL)
		{
			stream_free(stream);
			stream = NULL;
		}

		struct cipher_context* context = stream->internal_data;
		memset(context,0,sizeof(struct cipher_context));

		int ret = 0;

		char pers[] = "Mathias är bäst!";
	    entropy_init( &context->entropy );
	    if( ( ret = ctr_drbg_init( &context->ctr_drbg, entropy_func, &context->entropy,
	                               (unsigned char *) pers, strlen( pers ) ) ) != 0 )
	    {
	        printf( " failed\n  ! ctr_drbg_init returned %d\n", ret );
			stream_free(stream);
			return NULL;
	    }

	    if( ( ret = ssl_init( &context->ssl ) ) != 0 )
	    {
	        printf( " failed\n  ! ssl_init returned %d\n\n", ret );
			stream_free(stream);
			return NULL;
	    }

	    ssl_set_authmode( &context->ssl, SSL_VERIFY_OPTIONAL );

	    ssl_set_rng( &context->ssl, ctr_drbg_random, &context->ctr_drbg );
	//    ssl_set_dbg( &ctx->ssl, my_debug, stdout );
	    ssl_set_bio( &context->ssl, tls_net_recv, stream, tls_net_send, stream );

	    ssl_set_ciphersuites( &context->ssl, ssl_default_ciphersuites );
//	    ssl_set_session( &context->ssl, 1, 600, &context->ssn );
	}
	return stream;
}

stream_handle_t stream_new_ssl_client()
{
	stream_handle_t stream = stream_new_ssl();
	if (stream != NULL)
	{
		struct cipher_context* context = stream->internal_data;
		ssl_set_endpoint( &context->ssl, SSL_IS_CLIENT );
	}
	return stream;
}

stream_handle_t stream_new_ssl_server()
{
	stream_handle_t stream = stream_new_ssl();
	if (stream != NULL)
	{
		stream->state = STATE_HANDSHAKE;

		struct cipher_context* context = stream->internal_data;
		ssl_set_endpoint( &context->ssl, SSL_IS_SERVER );
	}
	return stream;
}

struct cipher_context* stream_get_cipher_context(stream_handle_t stream)
{
	assert(stream != NULL);

	return stream->internal_data;
}

void stream_set_authentication_callback(stream_handle_t stream, stream_authentication_callback_t callback, void* data)
{
	assert(stream != NULL);

	struct cipher_context* context = stream->internal_data;
	context->authentication_cb = callback;
	context->authentication_cb_data = data;
}
