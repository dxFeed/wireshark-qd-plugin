-- @file rmi_message_kind.lua
-- @brief Provides utility functions to handle RMI message kinds.

local rmi_message_kind = {
    REQUEST = 0x40,
    SERVER_CHANNEL_REQUEST = 0x41,
    CLIENT_CHANNEL_REQUEST = 0x42,
    SUCCESS_RESPONSE = 0x43,
    SERVER_CHANNEL_SUCCESS_RESPONSE = 0x44,
    CLIENT_CHANNEL_SUCCESS_RESPONSE = 0x45,
    ERROR_RESPONSE = 0x46,
    SERVER_CHANNEL_ERROR_RESPONSE = 0x47,
    CLIENT_CHANNEL_ERROR_RESPONSE = 0x48,
    DESCRIBE_SUBJECT = 0x49,
    DESCRIBE_OPERATION = 0x4A,
    ADVERTISE = 0x4B
}

function rmi_message_kind.has_channel(kind)
    return (
        kind == rmi_message_kind.CLIENT_CHANNEL_REQUEST or
        kind == rmi_message_kind.CLIENT_CHANNEL_ERROR_RESPONSE or
        kind == rmi_message_kind.CLIENT_CHANNEL_SUCCESS_RESPONSE
    ) or (
        kind == rmi_message_kind.SERVER_CHANNEL_REQUEST or
        kind == rmi_message_kind.SERVER_CHANNEL_ERROR_RESPONSE or
        kind == rmi_message_kind.SERVER_CHANNEL_SUCCESS_RESPONSE
    )
end

return rmi_message_kind
