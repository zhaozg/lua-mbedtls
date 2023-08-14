T=mbedtls

PREFIX		?=/usr/local
PKG_CONFIG	?=pkg-config
CC		:= $(CROSS)$(CC)
AR		:= $(CROSS)$(AR)
LD		:= $(CROSS)$(LD)
LUA		:=

#OS auto detect
ifneq (,$(TARGET_SYS))
  SYS		:= $(TARGET_SYS)
else
  SYS		:= $(shell gcc -dumpmachine)
endif

#Lua auto detect
LUA_VERSION	:= $(shell $(PKG_CONFIG) luajit --print-provides)
ifeq ($(LUA_VERSION),)
  # Not found luajit package, try lua
  LUA_VERSION	:= $(shell $(PKG_CONFIG) lua --print-provides)
  ifeq ($(LUA_VERSION),)
    # Not found lua package, try from prefix
    LUA_VERSION := $(shell lua -e "_,_,v=string.find(_VERSION,'Lua (.+)');print(v)")
    LUA_CFLAGS	?= -I$(PREFIX)/include
    LUA_LIBS	?= -L$(PREFIX)/lib #-llua
    LUA_LIBDIR	?= $(PREFIX)/lib/lua/$(LUA_VERSION)
    LUA		:= lua
  else
    # Found lua package
    LUA_VERSION	:= $(shell lua -e "_,_,v=string.find(_VERSION,'Lua (.+)');print(v)")
    LUA_CFLAGS	?= $(shell $(PKG_CONFIG) lua --cflags)
    LUA_LIBS	?= $(shell $(PKG_CONFIG) lua --libs)
    LUA_LIBDIR	?= $(PREFIX)/lib/lua/$(LUA_VERSION)
    LUA		:= lua
  endif
else
  # Found luajit package
  LUA_VERSION	:= $(shell luajit -e "_,_,v=string.find(_VERSION,'Lua (.+)');print(v)")
  LUA_CFLAGS	?= $(shell $(PKG_CONFIG) luajit --cflags)
  LUA_LIBS	?= $(shell $(PKG_CONFIG) luajit --libs)
  LUA_LIBDIR	?= $(PREFIX)/lib/lua/$(LUA_VERSION)
  LUA		:= luajit
endif

MBEDTLS_DIR	?= $(HOME)/work/extra/mbedtls
#mbedtls auto detect
mbedtls_CFLAGS	?= -I$(MBEDTLS_DIR)/include
mbedtls_LIBS	?= -L$(MBEDTLS_DIR)/build/library -lmbedcrypto -lmbedx509 -lmbedtls
TARGET  = $(MAKECMDGOALS)
ifeq (coveralls, ${TARGET})
  CFLAGS	+=-g -fprofile-arcs -ftest-coverage
  LDFLAGS	+=-g -fprofile-arcs
endif

ifeq (asan, ${TARGET})
  ASAN_LIB       = $(shell dirname $(shell dirname $(shell clang -print-libgcc-file-name)))/darwin/libclang_rt.asan_osx_dynamic.dylib
  CC             = clang
  LD             = clang
  CFLAGS	+=-g -O0 -fsanitize=address,undefined
  LDFLAGS       +=-g -fsanitize=address
endif

ifeq (debug, ${TARGET})
  CFLAGS	+=-g -Og
  LDFLAGS       +=-g -Og
endif

ifeq (valgrind, ${TARGET})
  CFLAGS	+=-g -O0
  LDFLAGS	+=-g -O0
endif

ifneq (, $(findstring linux, $(SYS)))
  # Do linux things
  CFLAGS	+= -fPIC
  LDFLAGS	+= -fPIC # -Wl,--no-undefined
endif

ifneq (, $(findstring apple, $(SYS)))
  # Do darwin things
  CFLAGS	+= -fPIC
  LDFLAGS	+= -fPIC -Wl,-undefined,dynamic_lookup -ldl
  MACOSX_DEPLOYMENT_TARGET="10.12"
  CC		:= MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET} $(CC)
endif

ifneq (, $(findstring mingw, $(SYS)))
  # Do mingw things
  CFLAGS	+= -DLUA_LIB -DLUA_BUILD_AS_DLL -DWIN32_LEAN_AND_MEAN
endif

ifneq (, $(findstring cygwin, $(SYS)))
  # Do cygwin things
  CFLAGS	+= -fPIC
endif

ifneq (, $(findstring iOS, $(SYS)))
  # Do iOS things
  CFLAGS	+= -fPIC
  LDFLAGS	+= -fPIC -ldl
endif

#custom config
ifeq (.config, $(wildcard .config))
  include .config
endif

CFLAGS		+= $(mbedtls_CFLAGS) $(LUA_CFLAGS) $(TARGET_FLAGS)
LDFLAGS		+= $(mbedtls_LIBS)
# Compilation directives
WARN_MIN	 = -Wall -Wno-unused-value -Wno-unused-function
WARN		 = -Wall
WARN_MOST	 = $(WARN) -W -Waggregate-return -Wcast-align -Wmissing-prototypes     \
		   -Wnested-externs -Wshadow -Wwrite-strings -pedantic
CFLAGS		+= -g -Og $(WARN_MIN) -DPTHREADS

OBJS=src/cipher.o src/md.o src/pk.o src/rng.o \
     src/net.o src/mbedtls.o src/ssl.o \
     src/x509_crl.o src/x509_crt.o src/x509_csr.o

.PHONY: all install test info doc coveralls asan

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $?

all: $T.so
	@echo "Target system: "$(SYS)

$T.so: lib$T.a $(OBJS)
	$(CC) -shared -o $@ $(OBJS) $(LDFLAGS)

lib$T.a: $(OBJS)
	$(AR) rcs $@ $?

install: all
	mkdir -p $(LUA_LIBDIR)
	echo cp $T.so $(LUA_LIBDIR)
	cp $T.so $(LUA_LIBDIR)
doc:
	ldoc src -d doc

info:
	@echo "Target system: "$(SYS)
	@echo "CC:" $(CC)
	@echo "AR:" $(AR)
	@echo "PREFIX:" $(PREFIX)

test:	all
	busted

debug: all

coveralls: test
ifeq ($(CI),)
	lcov -c -d src -o ${T}.info
	genhtml -o ${T}.html -t "${T} coverage" --num-spaces 2 ${T}.info
endif

valgrind: all
	cd test && LUA_CPATH=$(shell pwd)/?.so \
	valgrind --gen-suppressions=all --suppressions=../.github/lua-mbedtls.supp \
	--error-exitcode=1 --leak-check=full --child-silent-after-fork=yes \
	$(LUA) test.lua && cd ..

asan: all
	export ASAN_LIB=$(ASAN_LIB) && \
	cd test && LUA_CPATH=$(shell pwd)/?.so \
	DYLD_INSERT_LIBRARIES=$(ASAN_LIB) \
	$(LUA) test.lua && cd ..

clean:
	rm -rf $T.* lib$T.a $(OBJS) src/*.g*

# vim: ts=8 sw=8 noet
