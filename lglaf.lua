-- Wireshark Dissector for LG LAF protocol
-- Tested with Wireshark 2.0
--
-- Place it in ~/.config/wireshark/plugins/
-- (or ~/.wireshark/plugins/ if ~/.wireshark/ exists)
--
-- Alternatively start with: wireshark -X lua_script:path/to/lglaf.lua


local lglaf = Proto("lglaf", "LG LAF")

local usb_transfer_type = Field.new("usb.transfer_type")
local success, usb_endpoint = pcall(Field.new, "usb.endpoint_number")
if not success then
    -- Renamed since Wireshark v2.3.0rc0-1710-gf27f048ee1
    usb_endpoint = Field.new("usb.endpoint_address")
end

-- Main command header field
lglaf.fields.cmd = ProtoField.string("lglaf.command", "Command")
lglaf.fields.subcmd = ProtoField.string("lglaf.subcommand", "Subcommand")
-- Unknown / Unspecified header fields
lglaf.fields.arg1 = ProtoField.uint32("lglaf.arg1", "Argument 1", base.HEX_DEC)
lglaf.fields.arg2 = ProtoField.uint32("lglaf.arg2", "Argument 2", base.HEX_DEC)
lglaf.fields.arg3 = ProtoField.uint32("lglaf.arg3", "Argument 3", base.HEX_DEC)
lglaf.fields.arg4 = ProtoField.uint32("lglaf.arg4", "Argument 4", base.HEX_DEC)
-- Static header fields
lglaf.fields.len = ProtoField.uint32("lglaf.len", "Body length")
lglaf.fields.crc = ProtoField.uint32("lglaf.crc", "CRC", base.HEX)
lglaf.fields.cmd_inv = ProtoField.bytes("lglaf.command_inv", "Command (inverted)")
-- Unspecified header field
lglaf.fields.body = ProtoField.bytes("lglaf.body", "Body")
lglaf.fields.body_str = ProtoField.string("lglaf.body_str", "Body (text)")

function dissect_tx(tvb, pinfo, tree)
    local i
    local offset = 0
    for i = 1, 2 do
        tree:add_le(lglaf.fields.opts, tvb(offset, 4))
        offset = offset + 4
    end
    return offset
end

function lglaf.dissector(tvb, pinfo, tree)
    local offset
    local transfer_type = usb_transfer_type().value
    local endpoint = usb_endpoint().value

    -- Process only bulk packets from (EP 5) and to the device (EP 3)
    -- if not ((endpoint == 0x85 or endpoint == 3) and transfer_type == 3) then
    --     return 0
    -- end

    pinfo.cols.protocol = lglaf.name

    local lglaf_tree = tree:add(lglaf, tvb())
    
    -- Check if AT command
    if tvb(0, 2):string() == "AT" then
        pinfo.cols.info:set("AT Command")
        return
    -- Check if proper LAF
    elseif tvb:len() >= 0x20 and tvb(0, 4):le_uint() == bit.bnot(tvb(0x1c, 4):le_uint()) then
        pinfo.cols.info:set("LAF")
    else
        pinfo.cols.info:set("Continuation")
        if tvb:len() < 3 then
            return
        end
        -- Check if it could be HDLC
        if tvb(0, 1):uint() == 0xEF and tvb(-1):uint() == 0x7E then
            -- To be sure CRC16 could be checked, it's too resource intense tho
            pinfo.cols.info:set("Likely HDLC packet")
        end
        return
    end

    local next_offset = 0
    function add_dword(field)
        next_offset = next_offset + 4
        field_tvb = tvb(next_offset - 4, 4)
        lglaf_tree:add_le(field, field_tvb)
        return field_tvb
    end
    -- This is always a string
    add_dword(lglaf.fields.cmd)
    local v_args = {
        -- This can be a string
        add_dword(lglaf.fields.arg1),
        add_dword(lglaf.fields.arg2),
        add_dword(lglaf.fields.arg3),
        add_dword(lglaf.fields.arg4),
    }
    local v_len = add_dword(lglaf.fields.len)
    add_dword(lglaf.fields.crc)
    add_dword(lglaf.fields.cmd_inv)

    local cmd_string = tvb(0, 4):string()
    local subcmd = ""
    if cmd_string == "KILO" or cmd_string == "CTRL" or
       cmd_string == "INFO" or cmd_string == "RSVD" or
       cmd_string == "MISC" or cmd_string == "SNIF" or
       cmd_string == "OPCM" or cmd_string == "FUSE" or
       cmd_string == "CHCK" then
        subcmd = tvb(4,4):string()
    end
    pinfo.cols.info:set(cmd_string .. " " .. subcmd .. "(")
    for i, arg in ipairs(v_args) do
        if i > 1 then
            pinfo.cols.info:append(",");
        end
        pinfo.cols.info:append(string.format("0x%x", arg:le_uint()))
    end
    pinfo.cols.info:append(")")

    -- TODO desegmentation support
    local body_len = v_len:le_uint()
    if body_len > 0 then
        local body_tvb
        if (body_len - next_offset) > tvb(next_offset):len() then
            -- WRTE LAF packets give FULL length in header
            -- not only current payload length
            -- Workaround: Take what we get, not whats in the header
            body_tvb = tvb(next_offset) 
        else
            body_tvb = tvb(next_offset, body_len)
        end
        
        lglaf_tree:add(lglaf.fields.body, body_tvb)

        if cmd_string ~= "OPEN" and cmd_string ~= "EXEC" then
            -- Only those 2 commands contain a string in start of body
            return
        end

        local body_string = body_tvb:stringz()
        local body_string_len = #body_string + 1;
        lglaf_tree:add(lglaf.fields.body_str, body_tvb(0, body_string_len))

        pinfo.cols.info:append(" [" .. body_string_len ..  "] " .. body_string)
    end
end

function lglaf.init()
    local usb_product = DissectorTable.get("usb.product");
    usb_product:add(0x1004633e, lglaf) -- LG G3 (D855) or LG V10 (H962)
    usb_product:add(0x1004627f, lglaf) -- LG G3 (VS985)
    usb_product:add(0x10046298, lglaf) -- LG G4 (VS986)
    usb_product:add(0x1004633a, lglaf) -- LG V20(H910)
    local usb_bulk_dissectors = DissectorTable.get("usb.bulk")
    usb_bulk_dissectors:add(0xFF, lglaf)
    usb_bulk_dissectors:add(0xFFFF, lglaf)
end
