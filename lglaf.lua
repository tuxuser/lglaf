-- Wireshark Dissector for LG LAF protocol
-- Tested with Wireshark 2.0
--
-- Place it in ~/.config/wireshark/plugins/
-- (or ~/.wireshark/plugins/ if ~/.wireshark/ exists)
--
-- Alternatively start with: wireshark -X lua_script:path/to/lglaf.lua


local lglaf = Proto("lglaf", "LG LAF")

local usb_src = Field.new("usb.src")
local usb_dst = Field.new("usb.dst")
local usb_transfer_type = Field.new("usb.transfer_type")
local success, usb_endpoint = pcall(Field.new, "usb.endpoint_number")
if not success then
    -- Renamed since Wireshark v2.3.0rc0-1710-gf27f048ee1
    usb_endpoint = Field.new("usb.endpoint_address")
end

SEEK_MODE = {
    [0] = "SEEK_SET",
    [1] = "SEEK_CUR",
    [2] = "SEEK_END",
    [3] = "SEEK_DATA"
}

WRITE_TYPE = {
    [0x00] = "WRITE_EMMC_CONTINUOUS",
    [0x20] = "WRITE_EMMC_START",
    
    [0x09] = "WRITE_UFS_CONTINUOUS",
    [0x18] = "WRITE_UFS_START",
    [0x29] = "WRITE_UFS_END",
    [0x38] = "WRITE_UFS_SINGLE"
}

-- OPEN
lglaf.fields.open_resp_fd = ProtoField.uint32("lglaf.open_resp_fd", "File Descriptor", base.HEX_DEC) --arg0

-- CLOSE (CLSE)
lglaf.fields.close_fd = ProtoField.uint32("lglaf.close_fd", "File Descriptor", base.HEX_DEC) --arg0

-- HELLO (HELO)
lglaf.fields.helo_req_proto_version = ProtoField.uint32("lglaf.helo_req_proto_version", "Initial Protocol Version", base.HEX_DEC) --arg0
lglaf.fields.helo_req_unknown = ProtoField.uint32("lglaf.helo_req_unknown", "Unknown", base.HEX_DEC) --arg_opt1

lglaf.fields.helo_resp_proto_version = ProtoField.uint32("lglaf.helo_resp_proto_version", "Current Protocol Version", base.HEX_DEC) --arg0
lglaf.fields.helo_resp_min_proto_version = ProtoField.uint32("lglaf.helo_resp_min_proto_version", "Minimal Protocol Version", base.HEX_DEC) --arg1
lglaf.fields.helo_resp_code = ProtoField.uint32("lglaf.helo_resp_code", "Code", base.HEX_DEC) --arg_opt0
lglaf.fields.helo_resp_unknown = ProtoField.uint32("lglaf.helo_resp_unknown", "Unknown", base.HEX_DEC) --arg_opt1

-- CONTROL (CTRL)
lglaf.fields.ctrl_subcmd = ProtoField.string("lglaf.ctrl_subcmd", "Control Subcommand") -- arg0

-- WRITE (WRTE)
lglaf.fields.wrte_fd = ProtoField.uint32("lglaf.wrte_fd", "File Descriptor", base.HEX_DEC) -- arg0

lglaf.fields.wrte_req_offset= ProtoField.uint32("lglaf.wrte_req_offset", "Offset (block)", base.HEX_DEC) -- arg1
lglaf.fields.wrte_req_type = ProtoField.uint32("lglaf.wrte_req_type", "Type", base.HEX_DEC, WRITE_TYPE) -- arg_opt1

lglaf.fields.wrte_resp_offset = ProtoField.uint32("lglaf.wrte_resp_offset", "Offset (bytes)", base.HEX_DEC) -- arg1
lglaf.fields.wrte_resp_code = ProtoField.uint32("lglaf.wrte_resp_code", "Code", base.HEX_DEC) -- arg_opt0

-- READ
lglaf.fields.read_fd = ProtoField.uint32("lglaf.read_fd", "File Descriptor", base.HEX_DEC) -- arg0
lglaf.fields.read_offset = ProtoField.uint32("lglaf.read_req_offset", "Offset (block)", base.HEX_DEC) -- arg1
lglaf.fields.read_length = ProtoField.uint32("lglaf.read_req_length", "Length (bytes)", base.HEX_DEC) -- arg_opt0
lglaf.fields.read_mode = ProtoField.uint32("lglaf.read_req_mode", "Seek Mode", base.HEX_DEC, SEEK_MODE) -- arg_opt1

-- ERASE (ERSE)
lglaf.fields.erse_fd = ProtoField.uint32("lglaf.erse_fd", "File Descriptor", base.HEX_DEC) -- arg0
lglaf.fields.erse_offset = ProtoField.uint32("lglaf.erse_offset", "Offset (block)", base.HEX_DEC) -- arg1
lglaf.fields.erse_count = ProtoField.uint32("lglaf.erse_count", "Count (block)", base.HEX_DEC) -- arg_opt0

-- Challenge Response (KILO)
lglaf.fields.kilo_subcmd = ProtoField.string("lglaf.kilo_subcmd", "Kilo Subcommand") --arg0
lglaf.fields.kilo_mode = ProtoField.uint32("lglaf.kilo_mode", "Kilo Mode") -- arg_opt0

-- MISC
lglaf.fields.misc_subcmd = ProtoField.string("lglaf.misc_subcmd", "Misc Subcommand") --arg0

-- CHCK
lglaf.fields.chck_subcmd = ProtoField.string("lglaf.chck_subcmd", "Chck Subcommand") --arg0

-- OPCM
lglaf.fields.opcm_subcmd = ProtoField.string("lglaf.opcm_subcmd", "Opcm Subcommand") --arg0

-- INFO
lglaf.fields.info_subcmd = ProtoField.string("lglaf.info_subcmd", "Info Subcommand") --arg0

--
-- LAF HEADER
--
-- Main command header field
lglaf.fields.cmd = ProtoField.string("lglaf.command", "Command")
-- Unknown / Unspecified header fields
lglaf.fields.arg0 = ProtoField.uint32("lglaf.arg0", "Argument 0", base.HEX_DEC)
lglaf.fields.arg1 = ProtoField.uint32("lglaf.arg1", "Argument 1", base.HEX_DEC)
lglaf.fields.arg_opt0 = ProtoField.uint32("lglaf.arg_opt0", "Argument Opt 0", base.HEX_DEC)
lglaf.fields.arg_opt1 = ProtoField.uint32("lglaf.arg_opt1", "Argument Opt 1", base.HEX_DEC)
-- Static header fields
lglaf.fields.len = ProtoField.uint32("lglaf.len", "Body length")
lglaf.fields.crc = ProtoField.uint32("lglaf.crc", "CRC", base.HEX)
lglaf.fields.cmd_inv = ProtoField.bytes("lglaf.command_inv", "Command (inverted)")
-- Unspecified header field
lglaf.fields.body = ProtoField.bytes("lglaf.body", "Body")
lglaf.fields.body_str = ProtoField.string("lglaf.body_str", "Body (text)")

function dissect_open(tvb, pinfo, tree, direction)
    if direction == "RESPONSE" then
        tree:add_le(lglaf.fields.open_resp_fd, tvb(0, 4))
    else
        tree:add_le(lglaf.fields.arg0, tvb(0, 4))
    end
    tree:add_le(lglaf.fields.arg1, tvb(4, 4))
    tree:add_le(lglaf.fields.arg_opt0, tvb(8, 4))
    tree:add_le(lglaf.fields.arg_opt1, tvb(12, 4))
    if direction == "RESPONSE" then
        pinfo.cols.info:append("fd: "..tvb(0, 4):le_uint())
    end
end

function dissect_close(tvb, pinfo, tree, direction)
    tree:add_le(lglaf.fields.close_fd, tvb(0, 4))
    tree:add_le(lglaf.fields.arg1, tvb(4, 4))
    tree:add_le(lglaf.fields.arg_opt0, tvb(8, 4))
    tree:add_le(lglaf.fields.arg_opt1, tvb(12, 4))
    pinfo.cols.info:append("fd: "..tvb(0, 4):le_uint())
end

function dissect_read(tvb, pinfo, tree, direction)
    tree:add_le(lglaf.fields.read_fd, tvb(0, 4))
    tree:add_le(lglaf.fields.read_offset, tvb(4, 4))
    tree:add_le(lglaf.fields.read_length, tvb(8, 4))
    tree:add_le(lglaf.fields.read_mode, tvb(12, 4))
    local mode = tvb(12, 4):le_uint()
    local pinfo_str = string.format("fd: %d offset: 0x%x length: 0x%x mode: %s", 
        tvb(0, 4):le_uint(), tvb(4, 4):le_uint(), tvb(8, 4):le_uint(), SEEK_MODE[mode]
    )
    pinfo.cols.info:append(pinfo_str)
end

function dissect_write(tvb, pinfo, tree, direction)
    tree:add_le(lglaf.fields.wrte_fd, tvb(0, 4))
    if direction == "REQUEST" then
        tree:add_le(lglaf.fields.wrte_req_offset, tvb(4, 4))
        tree:add_le(lglaf.fields.arg_opt0, tvb(8, 4))
        tree:add_le(lglaf.fields.wrte_req_type, tvb(12, 4))
        local type = tvb(12, 4):le_uint()
        local pinfo_str = string.format("fd: %d offset: 0x%x type: %s",
            tvb(0, 4):le_uint(), tvb(4, 4):le_uint(), WRITE_TYPE[type]
        )
        pinfo.cols.info:append(pinfo_str)
    else
        tree:add_le(lglaf.fields.wrte_resp_offset, tvb(4, 4))
        tree:add_le(lglaf.fields.wrte_resp_code, tvb(8, 4))
        tree:add_le(lglaf.fields.arg_opt1, tvb(12, 4))
        local pinfo_str = string.format("fd: %d offset: 0x%x code: 0x%x",
            tvb(0, 4):le_uint(), tvb(4, 4):le_uint(), tvb(8 ,4):le_uint()
        )
        pinfo.cols.info:append(pinfo_str)
    end
end

function dissect_hello(tvb, pinfo, tree, direction)
    if direction == "REQUEST" then
        tree:add_le(lglaf.fields.helo_req_proto_version, tvb(0, 4))
        tree:add_le(lglaf.fields.arg1, tvb(4, 4))
        tree:add_le(lglaf.fields.arg_opt0, tvb(8, 4))
        tree:add_le(lglaf.fields.helo_req_unknown, tvb(12, 4))
        local pinfo_str = string.format("Version: 0x%x Unknown: 0x%x",
            tvb(0, 4):le_uint(), tvb(12, 4):le_uint()
        )
        pinfo.cols.info:append(pinfo_str)
    else
        tree:add_le(lglaf.fields.helo_resp_proto_version, tvb(0, 4))
        tree:add_le(lglaf.fields.helo_resp_min_proto_version, tvb(4, 4))
        tree:add_le(lglaf.fields.helo_resp_code, tvb(8, 4))
        tree:add_le(lglaf.fields.helo_resp_unknown, tvb(12, 4))
        local pinfo_str = string.format("Version: 0x%x MinVersion: 0x%x Code: 0x%x Unknown: 0x%x",
            tvb(0, 4):le_uint(), tvb(4, 4):le_uint(), tvb(8, 4):le_uint(), tvb(12, 4):le_uint()
        )
        pinfo.cols.info:append(pinfo_str)
    end
end

function dissect_control(tvb, pinfo, tree, direction)
    tree:add_le(lglaf.fields.ctrl_subcmd, tvb(0, 4))
    tree:add_le(lglaf.fields.arg1, tvb(4, 4))
    tree:add_le(lglaf.fields.arg_opt0, tvb(8, 4))
    tree:add_le(lglaf.fields.arg_opt1, tvb(12, 4))
    pinfo.cols.info:append(tvb(0, 4):string())
end

function dissect_erase(tvb, pinfo, tree, direction)
    tree:add_le(lglaf.fields.erse_fd, tvb(0, 4))
    tree:add_le(lglaf.fields.erse_offset, tvb(4, 4))
    tree:add_le(lglaf.fields.arg_count, tvb(8, 4))
    tree:add_le(lglaf.fields.arg_opt1, tvb(12, 4))
    local pinfo_str = string.format("fd: %d Offset: 0x%x Count: 0x%x",
        tvb(0, 4):le_uint(), tvb(4, 4):le_uint(), tvb(8, 4):le_uint()
    )
    pinfo.cols.info:append(pinfo_str)
end

function dissect_kilo(tvb, pinfo, tree, direction)
    tree:add_le(lglaf.fields.kilo_subcmd, tvb(0, 4))
    tree:add_le(lglaf.fields.arg1, tvb(4, 4))
    tree:add_le(lglaf.fields.kilo_mode, tvb(8, 4))
    tree:add_le(lglaf.fields.arg_opt1, tvb(12, 4))
    pinfo.cols.info:append(tvb(0 ,4):string().." Mode: "..tvb(8, 4):le_uint())
end

function dissect_misc(tvb, pinfo, tree, direction)
    tree:add_le(lglaf.fields.misc_subcmd, tvb(0, 4))
    tree:add_le(lglaf.fields.arg1, tvb(4, 4))
    tree:add_le(lglaf.fields.arg_opt0, tvb(8, 4))
    tree:add_le(lglaf.fields.arg_opt1, tvb(12, 4))
    pinfo.cols.info:append(tvb(0, 4):string())
end

function dissect_chck(tvb, pinfo, tree, direction)
    tree:add_le(lglaf.fields.chck_subcmd, tvb(0, 4))
    tree:add_le(lglaf.fields.arg1, tvb(4, 4))
    tree:add_le(lglaf.fields.arg_opt0, tvb(8, 4))
    tree:add_le(lglaf.fields.arg_opt1, tvb(12, 4))
    pinfo.cols.info:append(tvb(0, 4):string())
end

function dissect_opcm(tvb, pinfo, tree, direction)
    tree:add_le(lglaf.fields.opcm_subcmd, tvb(0, 4))
    tree:add_le(lglaf.fields.arg1, tvb(4, 4))
    tree:add_le(lglaf.fields.arg_opt0, tvb(8, 4))
    tree:add_le(lglaf.fields.arg_opt1, tvb(12, 4))
    pinfo.cols.info:append(tvb(0, 4):string())
end

function dissect_info(tvb, pinfo, tree, direction)
    tree:add_le(lglaf.fields.info_subcmd, tvb(0, 4))
    tree:add_le(lglaf.fields.arg1, tvb(4, 4))
    tree:add_le(lglaf.fields.arg_opt0, tvb(8, 4))
    tree:add_le(lglaf.fields.arg_opt1, tvb(12, 4))
    pinfo.cols.info:append(tvb(0, 4):string())
end

function dissect_other(tvb, pinfo, tree)
    tree:add_le(lglaf.fields.arg0, tvb(0, 4))
    tree:add_le(lglaf.fields.arg1, tvb(4, 4))
    tree:add_le(lglaf.fields.arg_opt0, tvb(8, 4))
    tree:add_le(lglaf.fields.arg_opt1, tvb(12, 4))
end

function lglaf.dissector(tvb, pinfo, tree)
    local offset
    local transfer_type = usb_transfer_type().value
    local endpoint = usb_endpoint().value
    local direction
    if usb_dst().value == "host" then
        direction = "RESPONSE"
    else
        direction = "REQUEST"
    end
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
        -- Should get overwritten later
        pinfo.cols.info:set("UNHANDLED LAF")
    else
        pinfo.cols.info:set("Continuation")
        if tvb:len() < 3 then
            return
        end
        -- Check if it could be HDLC
        if (tvb(0, 1):uint() == 0xEF or tvb(0, 1):uint() == 0x7E or tvb(0, 1):uint() == 0x02) and tvb(-1):uint() == 0x7E then
            -- To be sure CRC16 could be checked, it's too resource intense tho
            pinfo.cols.info:set("HDLC packet")
        end
        return
    end

    -- Assign COMMAND
    lglaf_tree:add_le(lglaf.fields.cmd, tvb(0, 4))
    local cmd_string = tvb(0, 4):string()
    local tvb_opts = tvb(4, 16)

    pinfo.cols.info:set(cmd_string.." "..direction.." ")
    if cmd_string == "OPEN" then
        dissect_open(tvb_opts, pinfo, lglaf_tree, direction)
    elseif cmd_string == "CLSE" then
        dissect_close(tvb_opts, pinfo, lglaf_tree, direction)
    elseif cmd_string == "READ" then
        dissect_read(tvb_opts, pinfo, lglaf_tree, direction)
    elseif cmd_string == "WRTE" then
        dissect_write(tvb_opts, pinfo, lglaf_tree, direction)
    elseif cmd_string == "HELO" then
        dissect_hello(tvb_opts, pinfo, lglaf_tree, direction)
    elseif cmd_string == "CTRL" then
        dissect_control(tvb_opts, pinfo, lglaf_tree, direction)
    elseif cmd_string == "ERSE" then
        dissect_erase(tvb_opts, pinfo, lglaf_tree, direction)
    elseif cmd_string == "KILO" then
        dissect_kilo(tvb_opts, pinfo, lglaf_tree, direction)
    elseif cmd_string == "MISC" then
        dissect_misc(tvb_opts, pinfo, lglaf_tree, direction)
    elseif cmd_string == "CHCK" then
        dissect_chck(tvb_opts, pinfo, lglaf_tree, direction)
    elseif cmd_string == "OPCM" then
        dissect_opcm(tvb_opts, pinfo, lglaf_tree, direction)
    elseif cmd_string == "INFO" then
        dissect_info(tvb_opts, pinfo, lglaf_tree, direction)
    else
        dissect_other(tvb_opts, pinfo, lglaf_tree)
    end

    -- static fields
    lglaf_tree:add_le(lglaf.fields.len, tvb(20, 4))
    lglaf_tree:add_le(lglaf.fields.crc, tvb(24, 4))
    lglaf_tree:add_le(lglaf.fields.cmd_inv, tvb(28, 4))

    -- TODO desegmentation support
    local body_len = tvb(20, 4):le_uint()
    if body_len > 0 then
        local body_tvb = tvb(32)
        lglaf_tree:add(lglaf.fields.body, body_tvb)

        if cmd_string ~= "OPEN" and cmd_string ~= "EXEC" and cmd_string ~= "UNLK" and cmd_string ~= "MISC" then
            pinfo.cols.info:append(" [BODY]")
            return
        end

        local body_string = body_tvb:stringz()
        local body_string_len = #body_string + 1;
        lglaf_tree:add(lglaf.fields.body_str, body_tvb(0, body_string_len))

        pinfo.cols.info:append(" [" .. body_string_len ..  "] " .. body_string)
        if body_tvb:len() > body_string_len then
            -- We got additional data!
            pinfo.cols.info:append(" [BODY]")
        end
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
