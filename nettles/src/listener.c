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
#include <memory.h>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/util.h>
#include <event2/dns.h>

#include "listener.h"

// TODO Use reference counting

struct listener* listener_new()
{
	struct listener* listener = malloc(sizeof(struct listener));
	if (listener != NULL)
	{
		memset(listener,0,sizeof(struct listener));
	}
	return listener;
}

void listener_free(struct listener* listener)
{
	if (listener != NULL)
	{
		if (listener->listener != NULL)
		{
			evconnlistener_free(listener->listener);
			listener->listener = NULL;
		}

		// Clear it to catch use after free
		memset(listener,0,sizeof(struct listener));
		free(listener);
		listener = NULL;
	}
}

