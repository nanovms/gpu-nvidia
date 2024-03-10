/*******************************************************************************
    Copyright (c) 2020 NVIDIA Corporation

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to
    deal in the Software without restriction, including without limitation the
    rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
    sell copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be
        included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.

*******************************************************************************/

#include <uvm_nanos.h>

#include "uvm_rb_tree.h"

static uvm_rb_tree_node_t *get_uvm_rb_tree_node(rbnode rb_node)
{
    return rb_entry(rb_node, uvm_rb_tree_node_t, rb_node);
}

static uvm_rb_tree_node_t *uvm_rb_tree_find_node(uvm_rb_tree_t *tree,
                                                 NvU64 key,
                                                 uvm_rb_tree_node_t **parent,
                                                 uvm_rb_tree_node_t **next)
{
    rbnode rb_node = tree->rb_root.root;
    uvm_rb_tree_node_t *node = NULL;
    uvm_rb_tree_node_t *_parent = NULL;

    while (rb_node) {
        node = get_uvm_rb_tree_node(rb_node);

        if (key < node->key)
            rb_node = rb_node->c[0];
        else if (key > node->key)
            rb_node = rb_node->c[1];
        else
            break;

        _parent = node;
    }

    if (!rb_node)
        node = NULL;

    if (parent)
        *parent = _parent;
    if (next) {
        *next = NULL; // Handles the empty tree case
        if (node) {
            *next = uvm_rb_tree_next(tree, node);
        }
        else if (_parent) {
            if (_parent->key > key)
                *next = _parent;
            else
                *next = uvm_rb_tree_next(tree, _parent);
        }
    }

    return node;
}

closure_func_basic(rb_key_compare, int, uvm_rbt_compare,
                   rbnode a, rbnode b)
{
    uvm_rb_tree_node_t *node_a = get_uvm_rb_tree_node(a);
    uvm_rb_tree_node_t *node_b = get_uvm_rb_tree_node(b);
    NvU64 key_a = node_a->key;
    NvU64 key_b = node_b->key;

    return (key_a == key_b) ? 0 : ((key_a < key_b) ? -1 : 1);
}

void uvm_rb_tree_init(uvm_rb_tree_t *tree)
{
    memset(tree, 0, sizeof(*tree));
    init_rbtree(&tree->rb_root, init_closure_func(&tree->compare, rb_key_compare, uvm_rbt_compare),
                0);
    INIT_LIST_HEAD(&tree->head);
}

NV_STATUS uvm_rb_tree_insert(uvm_rb_tree_t *tree, uvm_rb_tree_node_t *node)
{
    uvm_rb_tree_node_t *match, *parent;

    match = uvm_rb_tree_find_node(tree, node->key, &parent, NULL);
    if (match)
        return NV_ERR_IN_USE;
    init_rbnode(&node->rb_node);

    // If there's no parent and we didn't match on the root node, the tree is
    // empty.
    if (!parent) {
        rbtree_insert_node(&tree->rb_root, &node->rb_node);
        list_add(&node->list, &tree->head);
        return NV_OK;
    }

    if (node->key < parent->key) {
        list_add_tail(&node->list, &parent->list);
    }
    else {
        list_add(&node->list, &parent->list);
    }

    rbtree_insert_node(&tree->rb_root, &node->rb_node);
    return NV_OK;
}

uvm_rb_tree_node_t *uvm_rb_tree_find(uvm_rb_tree_t *tree, NvU64 key)
{
    return uvm_rb_tree_find_node(tree, key, NULL, NULL);
}
