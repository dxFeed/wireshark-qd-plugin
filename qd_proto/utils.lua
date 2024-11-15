-- @file utils.lua
-- @brief Provides general utility functions.
local jvm_id = require("qd_proto.format.jvm_id")

local utils = {}

-- @brief Compact Format.
-- The Compact Format is a serialization format for integer numbers.
-- It uses encoding scheme with variable-length two's complement
-- big-endian format capable to encode 64-bits signed numbers.
-- The following table defines used serial format (the first byte is given
-- in bits with 'x' representing payload bit the remaining bytes are
-- given in bit count):
-- 0xxxxxxx     - for -64 to 64
-- 10xxxxxx  8x - for -8192 to 8192
-- 110xxxxx 16x - for -1048576 to 1048576
-- 1110xxxx 24x - for -134217728 to 134217728
-- 11110xxx 32x - for -17179869184 to 17179869184
-- 111110xx 40x - for -2199023255552 to 2199023255552
-- 1111110x 48x - for -281474976710656 to 281474976710656
-- 11111110 56x - for -36028797018963968 to 36028797018963968
-- 11111111 64x - for -9223372036854775808 to 9223372036854775808

-- Gets the length in bytes of an compact format.
-- @deprecated Use a compact_reader.lua
-- @param n The first byte in compact format.
-- @return The number of bytes.
function utils.get_compact_len(n)
    if n < 0x80 then
        return 1
    elseif n < 0xC0 then
        return 2
    elseif n < 0xE0 then
        return 3
    elseif n < 0xF0 then
        return 4
    elseif n < 0xF8 then
        return 5
    elseif n < 0xFC then
        return 6
    elseif n < 0xFE then
        return 7
    elseif n < 0xFF then
        return 8
    else
        return 9
    end
end

-- Result of buffer read functions.
local read_result = {
    -- Start position in buf (value position).
    start_pos = nil,
    -- Read value.
    val = nil,
    -- Sizeof val.
    sizeof = nil,
    -- Next position in buf, after val.
    next_pos = nil
}

-- Reads an integer value from the data input in a compact format.
-- @deprecated Use a compact_reader.lua
-- @note If actual encoded value does not fit into an int (32-bit) data type,
--       then it is truncated to int value (only lower 32 bits are returned)
-- @param buf The input buffer.
-- @param off The offset in input buffer.
-- @return read_result - if reading is successful;
--         nil         - if cannot read value from buffer
--                       (buffer is not long enough).
function utils.read_compact_int(buf, off)
    local start_pos = off
    if (off >= buf:len()) then return nil end
    local n = buf(off, 1):uint()
    local compact_len = utils.get_compact_len(n)
    local remainder_len = buf:len() - off
    if (compact_len > remainder_len) then return nil end

    off = off + 1
    if compact_len == 1 then
        n = bit.lshift(n, 25)
        n = bit.arshift(n, 25)
    elseif compact_len == 2 then
        n = bit.lshift(n, 8)
        n = n + buf(off, 1):uint()
        n = bit.lshift(n, 18)
        n = bit.arshift(n, 18)
    elseif compact_len == 3 then
        n = bit.lshift(n, 16)
        n = n + buf(off, 2):uint()
        n = bit.lshift(n, 11)
        n = bit.arshift(n, 11)
    elseif compact_len == 4 then
        n = bit.lshift(n, 24)
        n = n + buf(off, 3):uint()
        n = bit.lshift(n, 4)
        n = bit.arshift(n, 4)
    else
        -- The encoded number is possibly out of range,
        -- some bytes have to be skipped.
        while bit.band(bit.lshift(n, 1), 0x10) ~= 0 do
            n = bit.lshift(n, 1)
            off = off + 1
        end
        n = buf(off, 4):int()
    end

    read_result = {
        start_pos = start_pos,
        val = n,
        sizeof = compact_len,
        next_pos = start_pos + compact_len
    }
    return read_result
end

-- Reads an long value from the data input in a compact format.
-- @deprecated Use a compact_reader.lua
-- @param buf The input buffer.
-- @param off The offset in input buffer.
-- @return read_result - if reading is successful;
--         nil         - if cannot read value from buffer
--                       (buffer is not long enough).
function utils.read_compact_long(buf, off)
    local start_pos = off
    if (off >= buf:len()) then return nil end
    local n = buf(off, 1):uint()
    local compact_len = utils.get_compact_len(n)
    local remainder_len = buf:len() - off
    if (compact_len > remainder_len) then return nil end

    if (compact_len <= 4) then
        -- Length and offset have been checked above.
        read_result = utils.read_compact_int(buf, off)
        read_result.val = utils.int_to_long(read_result.val)
        return read_result
    end

    off = off + 1
    if compact_len == 5 then
        n = bit.lshift(n, 29)
        n = bit.arshift(n, 29)
    elseif compact_len == 6 then
        n = bit.lshift(n, 8)
        n = n + buf(off, 1):uint()
        off = off + 1
        n = bit.lshift(n, 22)
        n = bit.arshift(n, 22)
    elseif compact_len == 7 then
        n = bit.lshift(n, 16)
        n = n + buf(off, 2):uint()
        off = off + 2
        n = bit.lshift(n, 15)
        n = bit.arshift(n, 15)
    elseif compact_len == 8 then
        n = buf(off, 1):uint()
        off = off + 1
        n = bit.lshift(n, 16)
        n = n + buf(off, 2):uint()
        off = off + 2
    else
        n = buf(off, 4):uint()
        off = off + 4
    end
    n = Int64(buf(off, 4):uint(), n)

    read_result = {
        start_pos = start_pos,
        val = n,
        sizeof = compact_len,
        next_pos = start_pos + compact_len
    }
    return read_result
end

-- Reads a UTF-8 string from the data input.
-- @deprecated Use a string_reader.lua
-- @note The string in the buffer is stored in the following form:
--       [string_len(compact_int)] + [string].
--       The return value specifies start_pos, sizeof, and next_pos,
--       including the string_len field.
-- @param buf The input buffer.
-- @param off The offset in input buffer.
-- @return read_result - if reading is successful;
--         nil         - if cannot read value from buffer.
function utils.read_utf8_string(buf, off)
    local start_pos = off
    local string_len = utils.read_compact_int(buf, off)
    if (string_len == nil or string_len.val < 0) then return nil end
    off = string_len.next_pos
    local string = ""
    if string_len.val ~= 0 then
        string = buf(off, string_len.val):raw();
        if (string == nil) then return nil end
    end

    read_result = {
        start_pos = start_pos,
        val = string,
        sizeof = string_len.sizeof + string_len.val,
        next_pos = off + string_len.val
    }
    return read_result
end

-- Converts an int to a long.
-- @param val The integer num (32-bit signed).
-- @return The long num (64-bit signed).
function utils.int_to_long(val)
    val = Int64(val, 0)
    val = val:lshift(32)
    val = val:arshift(32)
    return val
end

-- Converts an enumeration table to a string table.
-- @param enum_table The enum table.
-- @return The string table.
function utils.enum_tbl_to_str_tbl(enum_table)
    local string_table = {}
    for name, num in pairs(enum_table) do string_table[num] = name end
    return string_table
end

-- Converts an enumeration value to a string.
-- @param enum_table The enum table.
-- @param val  The value in the enum table.
-- @return string - if the conversion was successful;
--         nil -    if not.
function utils.enum_val_to_str(enum_table, val)
    return utils.enum_tbl_to_str_tbl(enum_table)[val]
end

-- Appends the source table to the destination table.
-- @note The tables must have "numbered" keys.
-- @param dst The destination table.
-- @param src The source table.
function utils.append_to_table(dst, src)
    -- The first element has always index 1, not 0.
    local n = #dst + 1
    for _, field in pairs(src) do
        dst[n] = field
        n = n + 1
    end
end

-- Sets the first num elements of the table to the specified value.
-- @param tbl The table for set.
-- @param off The offset in the table.
-- @param val The specific value.
-- @param num The number of elements.
function utils.set_tbl(tbl, off, val, num)
    for i = off, num, 1 do tbl[i] = val end
end

-- Compares two tables.
-- @param a The first table.
-- @param b The second table.
-- @return true  - if the tables are the same;
--         false - if not.
function utils.compare_tbl(a, b)
    if #a ~= #b then return false end
    for k, _ in pairs(a) do if a[k] ~= b[k] then return false end end
    return true
end

-- Converts UTF-8 codepoint to UTF-8 char.
-- @param codepoint The codepoint.
-- @return The character (1-4 bytes) in utf-8 encoding.
function utils.codepoint_to_char(codepoint)
    local byte_tbl = {}
    utils.set_tbl(byte_tbl, 0, 0, 1)
    local i = 1
    codepoint = bit.band(codepoint, 0xFFFFFFFF)
    while codepoint ~= 0 and i <= 4 do
        local byte = bit.band(bit.rshift(codepoint, 24), 0xFF)
        if (byte ~= 0) then
            byte_tbl[i] = byte
            i = i + 1
        end
        codepoint = bit.lshift(codepoint, 8)
    end

    -- Function string.char() cannot contain trailing zeros 
    -- and you can't pass a table as an argument.
    if (#byte_tbl == 1) then
        return string.char(byte_tbl[1])
    elseif (#byte_tbl == 2) then
        return string.char(byte_tbl[1], byte_tbl[2])
    elseif (#byte_tbl == 3) then
        return string.char(byte_tbl[1], byte_tbl[2], byte_tbl[3])
    else
        -- Maximum codepoint size.
        return string.char(byte_tbl[1], byte_tbl[2], byte_tbl[3], byte_tbl[4])
    end
end

-- Checks if a string is empty.
-- @param str The string.
-- @return true  - if the string is empty;
--         false - if the string not empty.
function utils.is_empty_str(str) return str == nil or str == '' end

-- Extracts a filename from a path.
-- @param path The path to the file.
-- @return The filename.
function utils.get_filename(path) return path:match("([^\\]-)$") end

-- Converts time in milliseconds to NSTime (with seconds and nanoseconds).
-- @param millis The UTC time in millisecond.
-- @return The NSTime object (with seconds and nanoseconds).
function utils.millis_to_nstime(millis)
    -- Gets the time in second.
    local seconds = (millis / 1000):tonumber()
    -- Gets the remainder in nanoseconds
    local nanoseconds_remainder = (millis % 1000):tonumber() * 1000000
    -- Returns NSTime object.
    return NSTime(seconds, nanoseconds_remainder)
end

-- Inserts substring into string on certain position number of counts.
-- @param str The source string.
-- @param sub The source substring.
-- @param pos The position in source string.
-- @param count The number of counts.
-- @return The result string.
function utils.insert_str(str, sub, pos, count)
    for i = 1, count, 1 do str = str:gsub('()', {[pos] = sub}) end
    return str
end

-- Checks if a flag is set.
-- @param flags The bit flags.
-- @param flag The flag for check.
-- @return true - if if the flag is set;
--         false - if not.
function utils.is_flag_set(flags, flag)
    if (flags == nil or flag == nil) then return false end
    return bit.band(flags, flag) ~= 0
end

-- Converts an bit flags from enum to a string.
-- @param enum_table The enum table.
-- @param flags  The flags value.
-- @return string - if the conversion was successful;
--         nil -    if not.
function utils.bit_flags_to_str(enum_table, flags)
    local str_table = utils.enum_tbl_to_str_tbl(enum_table)
    if (str_table == nil) then return nil end
    local str = ""
    local mask = 1
    while (flags ~= 0) do
        local mask_val = bit.band(flags, mask)
        if (mask_val ~= 0) then
            if (utils.is_empty_str(str) == false) then
                str = str .. " | "
            end
            str = str .. str_table[mask_val]
            flags = bit.band(flags, bit.bnot(mask_val))
        end
        mask = bit.lshift(mask, 1)
    end
    return str
end

-- Adds an endpoint subtree to the given tree structure.
-- This function reads JVM UID, name, and ID from the stream,
-- constructs a subtree with the extracted information, and appends it to the main tree.
-- @param tree The main tree structure to which the subtree will be added.
-- @param tree_name The name of the subtree to be added.
-- @param stream The stream object from which data is read.
-- @return sub The newly created subtree containing the endpoint information;
--         returns nil if the JVM ID is not found.
function utils.add_endpoint_subtree(tree, tree_name, stream)
    local start_pos = stream:get_current_pos()
    
    local length = stream:read_compact_long()
    if (length <= 0) then 
        local name, name_range = stream:read_utf8_str()
        local id, id_range = stream:read_compact_long()

        local total_range = stream:get_range(start_pos, stream:get_current_pos())
        local sub = tree:add(total_range, tree_name .. ": ")
        sub:append_text(name)
        return sub
    end
    stream:set_current_pos(start_pos)

    local jvm_uid, jvm_uid_range = stream:read_byte_array()
    if (jvm_uid == nil) then
        return
    end

    local jvm_base52_text = jvm_id.toString(jvm_uid);
    local name, name_range = stream:read_utf8_str()
    local id, id_range = stream:read_compact_long()

    local total_range = stream:get_range(start_pos, stream:get_current_pos())

    local sub = tree:add(total_range, tree_name .. ": ")
    sub:add(jvm_uid_range, "JVM UID: " .. jvm_uid:tohex())
    sub:add(jvm_uid_range, "JVM ID: " .. jvm_base52_text)
    sub:add(name_range, "Name: " .. name)
    sub:add(id_range, "ID: " .. id)            
    sub:append_text(name .. "@" .. jvm_base52_text)
    sub:append_text(", ID: " .. id)
    return sub
end

-- Marshals a byte array into a string if it follows the expected format.
-- This function checks the magic number and version, verifies the type code,
-- and then extracts the string content based on the specified length.
-- @param arr  The byte array to be marshaled.
-- @return string - The extracted string if the byte array is valid;
--         hex string representation of the array if the format is invalid.
function utils.marshal_string(arr)   
    -- Check magic and version. 
    local magic = arr:get_index(0) * 256 + arr:get_index(1)
    local version = arr:get_index(2) * 256 + arr:get_index(3)
    local signature = magic << 16 | version;
    if magic ~= 0xACED or version ~= 0x0005 then
         return arr:tohex();
    end

    -- Read type.
    local type_code = arr:get_index(4)
    if type_code ~= 0x74 then
        return arr:tohex();
    end
    
    -- Read length.
    local length = arr:get_index(5) * 256 + arr:get_index(6)
    
    -- Read content.
    local str = ""
    for i = 7, 6 + length do
        str = str .. string.char(arr:get_index(i))
    end
    
    return str
end

return utils
