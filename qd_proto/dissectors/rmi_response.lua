-- @file rmi_response.lua
-- @brief The RMI_RESPONSE message dissector.
local stream_reader = require("qd_proto.io.stream_reader")
local utils = require("qd_proto.utils")
local rmi_message_kind = require("qd_proto.rmi_message_kind")

local rmi_response = {}

-- List of RMI_RESPONSE fields to display in Wireshark.
rmi_response.ws_fields = {
    request_id = ProtoField.int64("qd.rmi_response.request_id", "Request ID", base.DEC),
    kind = ProtoField.string("qd.rmi_response.kind", "Kind", base.UNICODE),
    channel_id = ProtoField.int64("qd.rmi_response.channel_id", "Channel ID", base.DEC),
    marshal = ProtoField.string("qd.rmi_response.marshal", "Marshal", base.UNICODE),
}

-- Displays RMI_RESPONSE message in Wireshark.
-- @param stream Represents the input buffer.
-- @param tree The tree for display.
local function display(stream, tree)
    local ws_fields = rmi_response.ws_fields

    local request_id, request_id_range = stream:read_compact_long()
    tree:add(ws_fields.request_id, request_id_range, request_id)

    local kind, kind_range = stream:read_compact_int()
    tree:add(ws_fields.kind, kind_range, utils.enum_val_to_str(rmi_message_kind, kind))

    if (rmi_message_kind.has_channel(kind)) then
        local channel_id, channel_id_range = stream:read_compact_long()
        tree:add(ws_fields.channel_id, channel_id_range, channel_id)
    end

    -- Parses route.
    local count = stream:read_compact_int()
    if (count > 0) then
        for _ = 1, count, 1 do
            utils.add_endpoint_subtree(tree, "Route", stream)
        end    
    end

    local marshal, marshal_range = stream:read_byte_array()
    tree:add(ws_fields.marshal, marshal_range, marshal:tohex())
end

-- Dissects the RMI_RESPONSE message.
-- @param proto The protocol object.
-- @param tvb_buf The input buffer.
-- @param packet_info The packet information.
-- @param subtree The tree for display fields in Wireshark.
function rmi_response.dissect(proto, tvb_buf, packet_info, subtree)
    local res, err = pcall(function()
        local sr = stream_reader:new(tvb_buf, 0)
        while (sr:is_empty() ~= true) do display(sr, subtree) end
    end)
    if (res == false) then error(err) end
end

return rmi_response
