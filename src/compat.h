#ifndef LMBEDTLS_COMPAT_H

#if (LUA_VERSION_NUM == 501)

#define lua_rawlen(L, i) lua_objlen(L, i)

#if !defined(luaL_newlib)
static inline void *luaL_testudata (lua_State *L, int i, const char *tname) {
  void *p = lua_touserdata(L, i);
  luaL_checkstack(L, 2, "not enough stack slots");
  if (p == NULL || !lua_getmetatable(L, i))
    return NULL;
  else {
    int res = 0;
    luaL_getmetatable(L, tname);
    res = lua_rawequal(L, -1, -2);
    lua_pop(L, 2);
    if (!res)
      p = NULL;
  }
  return p;
}

#define luaL_newlib(L, R)                                                      \
  do {                                                                         \
    lua_newtable(L);                                                           \
    luaL_register(L, NULL, R);                                                 \
  } while (0)

#endif /* luaL_newlib */

#define lua_rawgetp(L, idx, key)                                               \
  (lua_pushlightuserdata(L, key), lua_rawget(L, idx))
#define lua_rawsetp(L, idx, key)                                               \
  (lua_pushlightuserdata(L, key), lua_insert(L, -2), lua_rawset(L, idx))
#define lua_getuservalue(L, idx) lua_getfenv(L, idx)
#define lua_setuservalue(L, idx) lua_setfenv(L, idx)
#define lua_cpcall(L, func, arg)                                               \
  (lua_pushcfunction(L, func), lua_pushlightuserdata(L, arg),                  \
   lua_pcall(L, 1, 0, 0))

static inline int lua_absindex (lua_State *L, int idx) {
    return idx < 0 ? lua_gettop(L) + 1 + idx : idx;
}

#endif

#endif /* LMBEDTLS_COMPAT_H */
