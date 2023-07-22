/*
 * Copyright (c) 2002-2020 Lee Salzman
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "chipvpn/list.h"
#include <stddef.h>

void chipvpn_list_clear(chipvpn_list_t *list) {
	list->sentinel.next = &list->sentinel;
	list->sentinel.previous = &list->sentinel;
}

chipvpn_list_node_t *chipvpn_list_insert(chipvpn_list_node_t *position, void *data) {
	chipvpn_list_node_t *result = (chipvpn_list_node_t*)data;

	result->previous = position->previous;
	result->next = position;

	result->previous->next = result;
	position->previous = result;

	return result;
}

void *chipvpn_list_remove(chipvpn_list_node_t *position) {
	position->previous->next = position->next;
	position->next->previous = position->previous;

	return position;
}

chipvpn_list_node_t *chipvpn_list_move(chipvpn_list_node_t *position, void *dataFirst, void *dataLast) {
	chipvpn_list_node_t *first = (chipvpn_list_node_t*)dataFirst;
	chipvpn_list_node_t *last = (chipvpn_list_node_t*)dataLast;

	first->previous->next = last->next;
	last->next->previous = first->previous;

	first->previous = position->previous;
	last->next = position;

	first->previous->next = first;
	position->previous = last;

	return first;
}

size_t chipvpn_list_size(chipvpn_list_t *list) {
	size_t size = 0;

	for(chipvpn_list_node_t *position = chipvpn_list_begin(list); position != chipvpn_list_end(list); position = chipvpn_list_next(position)) {
		++size;
	}

	return size;
}