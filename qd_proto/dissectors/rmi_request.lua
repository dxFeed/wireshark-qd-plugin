-- @file rmi_request.lua
-- @brief The RMI_REQUEST message dissector.
local stream_reader = require("qd_proto.io.stream_reader")
local utils = require("qd_proto.utils")
local rmi_message_kind = require("qd_proto.rmi_message_kind")
local rmi_request_type = require("qd_proto.rmi_request_type")

local rmi_request = {}

-- List of RMI_REQUEST fields to display in Wireshark.
rmi_request.ws_fields = {
    request_id = ProtoField.int64("qd.rmi_request.request_id", "Request ID", base.DEC),
    kind = ProtoField.string("qd.rmi_request.kind", "Kind", base.UNICODE),
    channel_id = ProtoField.int64("qd.rmi_request.channel_id", "Channel ID", base.DEC),
    request_type = ProtoField.string("qd.rmi_request.request_type", "Request Type", base.UNICODE),
    subject_id = ProtoField.uint32("qd.rmi_request.subject_id", "Subject ID", base.DEC),
    operation_id = ProtoField.uint32("qd.rmi_request.opertaion_id", "Operation ID", base.DEC),
    marshal = ProtoField.string("qd.rmi_response.marshal", "Marshal", base.UNICODE),
}

-- Displays RMI_REQUEST message in Wireshark.
-- @param stream Represents the input buffer.
-- @param tree The tree for display.
local function display(stream, tree)
    local ws_fields = rmi_request.ws_fields

    local request_id, request_id_range = stream:read_compact_long()
    tree:add(ws_fields.request_id, request_id_range, request_id)

    local kind, kind_range = stream:read_compact_int()
    tree:add(ws_fields.kind, kind_range, utils.enum_val_to_str(rmi_message_kind, kind))

    if (rmi_message_kind.has_channel(kind)) then
        local channel_id, channel_id_range = stream:read_compact_long()
        tree:add(ws_fields.channel_id, channel_id_range, channel_id)
    end

    local request_type, request_type_range = stream:read_compact_int()
    tree:add(ws_fields.request_type, request_type_range, utils.enum_val_to_str(rmi_request_type, request_type))

    -- Parses route.
    local count = stream:read_compact_int()
    if (count > 0) then
        for _ = 1, count, 1 do
            utils.add_endpoint_subtree(tree, "Route", stream)
        end    
    end

    utils.add_endpoint_subtree(tree, "Service ID", stream)

    local subject_id, subject_id_range = stream:read_compact_int()
    tree:add(ws_fields.subject_id, subject_id_range, subject_id)

    local operation_id, operation_id_range = stream:read_compact_int()
    tree:add(ws_fields.operation_id, operation_id_range, operation_id)

    local marshal, marshal_range = stream:read_byte_array()
    tree:add(ws_fields.marshal, marshal_range, marshal:tohex())    
end

-- Dissects the RMI_REQUEST message.
-- @param proto The protocol object.
-- @param tvb_buf The input buffer.
-- @param packet_info The packet information.
-- @param subtree The tree for display fields in Wireshark.
function rmi_request.dissect(proto, tvb_buf, packet_info, subtree)
    local res, err = pcall(function()
        local sr = stream_reader:new(tvb_buf, 0)
        while (sr:is_empty() ~= true) do display(sr, subtree) end
    end)
    if (res == false) then error(err) end
end

return rmi_request
