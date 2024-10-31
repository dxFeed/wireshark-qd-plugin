-- @file decimal.lua
-- The Unique ID for the each JVM.

-- Constants
local TEXT_LENGTH = 5 -- Length of the resulting JVM ID.
local CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

local jvm_id = {}

-- Function to convert ByteArray to string representation JVM_ID. 
function jvm_id.toString(arr)
    local temp = 0
    local length = arr:len()
    local startIndex = math.max(0, length - 4)

    for i = startIndex, length - 1 do
        temp = (temp << 8) | (arr:get_index(i) & 0xFF)
    end

    -- Process temp as a signed 32-bit integer.
    if temp >= 0x80000000 then
        temp = temp - 0x100000000
    end

    local result = {}

    -- Generate the JVM_ID string
    for i = TEXT_LENGTH, 1, -1 do
        local index = math.abs(math.fmod(temp, #CHARS)) + 1  -- lua indices start at 1.
        result[i] = string.sub(CHARS, index, index)
        temp = math.floor(temp / #CHARS)
        if (temp < 0) then
            temp = temp + 1
        end
    end

    return table.concat(result)
end

return jvm_id
