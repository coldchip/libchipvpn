/*
 * Copyright (c) 2002-2020 Lee Salzman
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef LIST_H
#define LIST_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>

typedef struct _chipvpn_list_node_t {
	struct _chipvpn_list_node_t *next;
	struct _chipvpn_list_node_t *previous;
} chipvpn_list_node_t;

typedef struct {
	chipvpn_list_node_t sentinel;
} chipvpn_list_t;

extern void                     chipvpn_list_clear(chipvpn_list_t *list);
extern chipvpn_list_node_t     *chipvpn_list_insert(chipvpn_list_node_t *position, void *data);
extern void                    *chipvpn_list_remove(chipvpn_list_node_t *position);
extern chipvpn_list_node_t     *chipvpn_list_move(chipvpn_list_node_t *position, void *dataFirst, void *dataLast);
extern size_t                   chipvpn_list_size(chipvpn_list_t *list);

#define chipvpn_list_begin(list) ((list)->sentinel.next)
#define chipvpn_list_end(list) (&(list)->sentinel)

#define chipvpn_list_empty(list) (chipvpn_list_begin(list) == chipvpn_list_end(list))

#define chipvpn_list_next(iterator) ((iterator)->next)
#define chipvpn_list_previous(iterator) ((iterator)->previous)

#define chipvpn_list_front(list) ((void *) (list)->sentinel.next)
#define chipvpn_list_back(list) ((void *) (list)->sentinel.previous)

#ifdef __cplusplus
}
#endif

#endif