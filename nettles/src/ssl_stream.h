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

#ifndef SSL_STREAM_H_
#define SSL_STREAM_H_

#include "stream.h"

typedef void (*stream_authentication_callback_t)(stream_handle_t stream, void* data);

#define HANDSHAKE_DONE 1

struct cipher_context {
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    ssl_context ssl;
    ssl_session ssn;

    x509_cert ca;
    x509_crl crl;
    x509_cert certificate;
    rsa_context rsa;

    stream_authentication_callback_t authentication_cb;
    void* authentication_cb_data;
};

stream_handle_t stream_new_ssl_client();
stream_handle_t stream_new_ssl_server();

struct cipher_context* stream_get_cipher_context(stream_handle_t stream);

void stream_set_authentication_callback(stream_handle_t stream, stream_authentication_callback_t callback, void* data);

#endif /* SSL_STREAM_H_ */
