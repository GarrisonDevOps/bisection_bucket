GENCCODE_ASSEMBLY_TYPE=-a gcc
SO=so
SOBJ=so
A=a
LIBPREFIX=lib
LIB_EXT_ORDER=.78.3
COMPILE=gcc -I/opt/gitlab/embedded/include -O3 -D_FORTIFY_SOURCE=2 -fstack-protector -D_REENTRANT  -DU_HAVE_ELF_H=1  -DU_ALL_IMPLEMENTATION -DU_ATTRIBUTE_DEPRECATED= -O3 -I/opt/gitlab/embedded/include -O3 -D_FORTIFY_SOURCE=2 -fstack-protector -std=c11 -Wall -pedantic -Wshadow -Wpointer-arith -Wmissing-prototypes -Wwrite-strings   -c
LIBFLAGS=-I/opt/gitlab/embedded/include -DPIC -fPIC
GENLIB=gcc -O3 -I/opt/gitlab/embedded/include -O3 -D_FORTIFY_SOURCE=2 -fstack-protector -std=c11 -Wall -pedantic -Wshadow -Wpointer-arith -Wmissing-prototypes -Wwrite-strings   -Wl,-rpath,/opt/gitlab/embedded/lib -L/opt/gitlab/embedded/lib  -shared -Wl,-Bsymbolic
LDICUDTFLAGS=-nodefaultlibs -nostdlib
LD_SONAME=-Wl,-soname -Wl,
RPATH_FLAGS=
BIR_LDFLAGS=-Wl,-Bsymbolic
AR=ar
ARFLAGS=r
RANLIB=ranlib
INSTALL_CMD=/usr/bin/install -c
