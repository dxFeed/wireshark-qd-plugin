-- @file rmi_describe_subject.lua
-- @brief The RMI_DESCRIBE_SUBJECT message dissector.
local stream_reader = require("qd_proto.io.stream_reader")
local utils = require("qd_proto.utils")

local rmi_describe_subject = {}

-- List of RMI_DESCRIBE_SUBJECT fields to display in Wireshark.
rmi_describe_subject.ws_fields = {
    id = ProtoField.uint32("qd.rmi_describe_subject.id", "ID", base.DEC),
    subject = ProtoField.string("qd.rmi_describe_subject.subject", "Subject", base.UNICODE),
}

-- Displays RMI_DESCRIBE_SUBJECT message in Wireshark.
-- @param stream Represents the input buffer.
-- @param tree The tree for display.
local function display(stream, tree)
    local ws_fields = rmi_describe_subject.ws_fields

    local id, id_range = stream:read_compact_int()
    tree:add(ws_fields.id, id_range, id)

    local subject, subject_range = stream:read_byte_array()
    tree:add(ws_fields.subject, subject_range, utils.marshal_string(subject))
end

-- Dissects the RMI_DESCRIBE_SUBJECT message.
-- @param proto The protocol object.
-- @param tvb_buf The input buffer.
-- @param packet_info The packet information.
-- @param subtree The tree for display fields in Wireshark.
function rmi_describe_subject.dissect(proto, tvb_buf, packet_info, subtree)
    local res, err = pcall(function()
        local sr = stream_reader:new(tvb_buf, 0)
        while (sr:is_empty() ~= true) do display(sr, subtree) end
    end)
    if (res == false) then error(err) end
end

return rmi_describe_subject
