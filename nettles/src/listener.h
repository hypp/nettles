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

#ifndef LISTENER_H_
#define LISTENER_H_

#include <lua.h>
#include <lauxlib.h>

struct listener {
	struct evconnlistener *listener;

	struct event_base *base;
	struct evdns_base *dns;
	lua_State *L;
};

struct listener* listener_new();

void listener_free(struct listener* listener);

#endif /* LISTENER_H_ */
