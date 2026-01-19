# Investigation: Multiple Client Connections on One Socket in lsquic

## Question
Can multiple lsquic client connections to different destinations use the same UDP socket?

## TL;DR
**No, not with default settings** - the library explicitly prevents this when `ENG_CONNS_BY_ADDR` is set.

## Test Program
Created `bin/multi_dest_test.c` to test connecting to www.google.com and www.facebook.com simultaneously using one socket.

### Result
```
[ERROR] engine: cannot have more than one connection on the same port
```

## Root Cause Analysis

### Code Location: `src/liblsquic/lsquic_engine.c`

**Lines 1991-1996** in `lsquic_engine_connect()`:
```c
if (engine->flags & ENG_CONNS_BY_ADDR
                    && find_conn_by_addr(engine->conns_hash, local_sa))
{
    LSQ_ERROR("cannot have more than one connection on the same port");
    goto err;
}
```

**Lines 551-563** - `hash_conns_by_addr()` determines when to set `ENG_CONNS_BY_ADDR`:
```c
static int
hash_conns_by_addr (const struct lsquic_engine *engine)
{
    if (engine->flags & ENG_SERVER)
        return 0;
    if (engine->pub.enp_settings.es_versions & LSQUIC_FORCED_TCID0_VERSIONS)
        return 1;
    if ((engine->pub.enp_settings.es_versions & LSQUIC_GQUIC_HEADER_VERSIONS)
                                && engine->pub.enp_settings.es_support_tcid0)
        return 1;
    if (engine->pub.enp_settings.es_scid_len == 0)
        return 1;
    return 0;
}
```

## When `ENG_CONNS_BY_ADDR` is Set

The engine hashes connections by local address (IP:port) instead of connection ID when:

1. **Client mode** (not server), AND
2. One of:
   - Using old GQUIC versions with forced TCID0
   - Using GQUIC with `es_support_tcid0` enabled
   - **`es_scid_len == 0`** (no source connection ID)

In these cases, only ONE connection can exist per local address because there's no connection ID to disambiguate incoming packets.

## Why This Matters

### Server Side (works fine)
- One socket serves multiple clients
- Uses `IP_PKTINFO` to set source address per packet (line 1730 in `bin/test_common.c`)
- Hashes connections by connection ID

### Client Side (restricted)
- When `ENG_CONNS_BY_ADDR` is set: **ONE connection per socket**
- When NOT set (modern IETF QUIC with CIDs): theoretically multiple connections possible

## For Issue #613

The user's approach of "one socket per connection" aligns with the library's current design for clients. However, for modern IETF QUIC v1 with proper connection IDs (`es_scid_len > 0`), the `ENG_CONNS_BY_ADDR` flag should NOT be set, which would theoretically allow multiple connections per socket.

### Current Client Example Pattern
The example clients in `bin/` use one of:
1. `SPORT_CONNECT` flag → calls `connect()` to bind socket to single destination
2. One connection per socket anyway

## Recommendations

For users wanting "one engine, N connections" on a single socket:

1. **Use IETF QUIC v1** (not GQUIC)
2. **Ensure `es_scid_len > 0`** in engine settings
3. **Don't use `SPORT_CONNECT`** (don't call `connect()` on the socket)
4. Test if the library actually supports this - it may need modifications

The cleaner solution: **Accept "one socket per connection"** and let the OS handle the socket management.

## Files Modified

- `bin/multi_dest_test.c` - Test program (demonstrates the restriction)
- `bin/CMakeLists.txt` - Added build rules for test program

## Build and Run

```bash
cmake . && make multi_dest_test
./bin/multi_dest_test
```

## Conclusion

The library's current design for client connections assumes:
- **Either**: One connection per socket (current approach in issue #613)
- **Or**: Server mode with one socket serving many incoming connections

Multiple outgoing client connections sharing one socket is NOT supported when `ENG_CONNS_BY_ADDR` is set, which happens by default for certain QUIC configurations.
