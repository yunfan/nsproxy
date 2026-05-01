#pragma once
#include "proxy.h"
#include "loop.h"

struct proxy *tcpdns_create(struct loopctx *loop, userev_fn_t *userev,
                            void *userp);
