#!/bin/sh

prefix=/opt/gitlab/embedded
exec_prefix=/opt/gitlab/embedded
libdir=${exec_prefix}/lib

LD_PRELOAD=${libdir}/libjemalloc.so.2
export LD_PRELOAD
exec "$@"
