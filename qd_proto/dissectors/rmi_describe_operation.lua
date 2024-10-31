-- @file rmi_describe_operation.lua
-- @brief The RMI_DESCRIBE_OPERATION message dissector.
local stream_reader = require("qd_proto.io.stream_reader")

local rmi_describe_operation = {}

-- List of RMI_DESCRIBE_OPERATION fields to display in Wireshark.
rmi_describe_operation.ws_fields = {
    id = ProtoField.uint32("qd.rmi_describe_operation.id", "ID", base.DEC),
    operaion = ProtoField.string("qd.rmi_describe_operation.operaion", "Operation", base.UNICODE),
}

-- Displays RMI_DESCRIBE_OPERATION message in Wireshark.
-- @param stream Represents the input buffer.
-- @param tree The tree for display.
local function display(stream, tree)
    local ws_fields = rmi_describe_operation.ws_fields

    local id, id_range = stream:read_compact_int()
    tree:add(ws_fields.id, id_range, id)

    local operaion, operaion_range = stream:read_utf8_str()
    tree:add(ws_fields.operaion, operaion_range, operaion)
end

-- Dissects the RMI_DESCRIBE_OPERATION message.
-- @param proto The protocol object.
-- @param tvb_buf The input buffer.
-- @param packet_info The packet information.
-- @param subtree The tree for display fields in Wireshark.
function rmi_describe_operation.dissect(proto, tvb_buf, packet_info, subtree)
    local res, err = pcall(function()
        local sr = stream_reader:new(tvb_buf, 0)
        while (sr:is_empty() ~= true) do display(sr, subtree) end
    end)
    if (res == false) then error(err) end
end

return rmi_describe_operation
