-- Copyright (c) 2018 Phil Leblanc (modified for LuaJIT/bit library)
--[[
    Chacha20 stream encryption - Lua 5.1 / LuaJIT version
]]

local band, bor, bxor = bit.band, bit.bor, bit.bxor
local lshift, rshift, rol = bit.lshift, bit.rshift, bit.rol
local app, concat = table.insert, table.concat

ffi.cdef[[
    typedef struct { uint32_t v[16]; } chacha_state;
]]

------------------------------------------------------------

local function qround(st, x, y, z, w)
    local a, b, c, d = st[x], st[y], st[z], st[w]
    
    a = band(a + b, 0xffffffff)
    d = rol(bxor(d, a), 16)
    
    c = band(c + d, 0xffffffff)
    b = rol(bxor(b, c), 12)
    
    a = band(a + b, 0xffffffff)
    d = rol(bxor(d, a), 8)
    
    c = band(c + d, 0xffffffff)
    b = rol(bxor(b, c), 7)
    
    st[x], st[y], st[z], st[w] = a, b, c, d
end

local chacha20_state = ffi.new("chacha_state")
local chacha20_working_state = ffi.new("chacha_state")

local chacha20_block = function(key, counter, nonce)
    local st = chacha20_state.v
    local wst = chacha20_working_state.v
    
    -- initialize state
    st[0], st[1], st[2], st[3] = 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    for i = 0, 7 do st[i+4] = key[i] end
    st[12] = counter
    for i = 0, 2 do st[i+13] = nonce[i] end
    
    -- copy state
    for i = 0, 15 do wst[i] = st[i] end
    
    -- 20 rounds
    for _ = 1, 10 do
        qround(wst, 0,4,8,12)
        qround(wst, 1,5,9,13)
        qround(wst, 2,6,10,14)
        qround(wst, 3,7,11,15)
        qround(wst, 0,5,10,15)
        qround(wst, 1,6,11,12)
        qround(wst, 2,7,8,13)
        qround(wst, 3,4,9,14)
    end
    
    for i = 0, 15 do st[i] = band(st[i] + wst[i], 0xffffffff) end
    return st
end

local function str_to_u32(str, count)
    local arr = ffi.new("uint32_t[?]", count)
    ffi.copy(arr, str, count * 4)
    return arr
end

local function u32_to_str(arr, count)
    return ffi.string(arr, count * 4)
end

local chacha20_encrypt = function(key, counter, nonce, pt)
    assert(#key == 32, "key size must be 32")
    assert(#nonce == 12, "nonce size must be 12")
    
    local keya = str_to_u32(key, 8)
    local noncea = str_to_u32(nonce, 3)
    local t = {}
    local ptidx = 0
    local len = #pt
    
    local block_arr = ffi.new("uint32_t[16]")
    
    while ptidx < len do
        local keystream = chacha20_block(keya, counter, noncea)
        local chunk_size = math.min(64, len - ptidx)
        
        local chunk = pt:sub(ptidx + 1, ptidx + chunk_size)
        if chunk_size < 64 then chunk = chunk .. string.rep("\0", 64 - chunk_size) end
        
        ffi.copy(block_arr, chunk, 64)
        
        for i = 0, 15 do
            block_arr[i] = bxor(block_arr[i], keystream[i])
        end
        
        local encrypted_chunk = ffi.string(block_arr, chunk_size)
        app(t, encrypted_chunk)
        
        ptidx = ptidx + 64
        counter = band(counter + 1, 0xffffffff)
    end
    
    return concat(t)
end

------------------------------------------------------------
return {
    encrypt = chacha20_encrypt,
    decrypt = chacha20_encrypt, -- Symmetric
    key_size = 32,
    nonce_size = 12
}
