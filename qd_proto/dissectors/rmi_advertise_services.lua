-- @file rmi_advertise_services.lua
-- @brief The RMI_ADVERTISE_SERVICES message dissector.
local stream_reader = require("qd_proto.io.stream_reader")
local utils = require("qd_proto.utils")

local rmi_advertise_services = {}

-- List of RMI_ADVERTISE_SERVICES fields to display in Wireshark.
rmi_advertise_services.ws_fields = {}

-- Displays RMI_ADVERTISE_SERVICES message in Wireshark.
-- @param stream Represents the input buffer.
-- @param tree The tree for display.
local function display(stream, tree)
    local ws_fields = rmi_advertise_services.ws_fields

    while (stream:is_empty() ~= true) do
        local sub = utils.add_endpoint_subtree(tree, "Service", stream)

        local distance, distance_range = stream:read_compact_int()
        sub:add(distance_range, "Distance", distance)

        local count = stream:read_compact_int()
        if (count > 0) then
            for _ = 1, count, 1 do
                utils.add_endpoint_subtree(sub, "Node", stream)
            end    
        end

        count = stream:read_compact_int()
        if (count > 0) then
            for _ = 1, count, 1 do
                local start_pos = stream:get_current_pos()
                local key = stream:read_utf8_str()
                local val = stream:read_utf8_str()

                local range = stream:get_range(start_pos, stream:get_current_pos())
                sub:add(range, key .. ": " .. val)
            end
        end
    end
end

-- Dissects the RMI_ADVERTISE_SERVICES message.
-- @param proto The protocol object.
-- @param tvb_buf The input buffer.
-- @param packet_info The packet information.
-- @param subtree The tree for display fields in Wireshark.
function rmi_advertise_services.dissect(proto, tvb_buf, packet_info, subtree)
    local res, err = pcall(function()
        local sr = stream_reader:new(tvb_buf, 0)
        -- while (sr:is_empty() ~= true) do display(sr, subtree) end
        display(sr, subtree)
    end)
    if (res == false) then error(err) end
end

return rmi_advertise_services
