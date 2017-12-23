#!/usr/bin/env python
#
# Interactive shell for communication with LG devices in download mode (LAF).
#
# Copyright (C) 2015 Peter Wu <peter@lekensteyn.nl>
# Licensed under the MIT license <http://opensource.org/licenses/MIT>.

from __future__ import print_function
from contextlib import closing
import argparse, logging, struct, sys, binascii
from utils import crc16, text_unescape
from utils import invert_dword, parse_number_or_escape

# Enhanced prompt with history
try: import readline
except ImportError: pass
# Try USB interface
try: import usb.core, usb.util
except ImportError: pass
# Windows registry for serial port detection
try: import winreg
except ImportError:
    try: import _winreg as winreg
    except ImportError: winreg = None
# laf crypto for KILO challenge/response
try:
    from laf_crypto import LafCrypto
except ImportError:
    raise Exception("LAF Crypto failed to import!")
# Python 2/3 compat
try: input = raw_input
except: pass

_logger = logging.getLogger("LGLAF.py")

laf_error_codes = {
    0x80000000: "FAILED",
    0x80000001: "INVALID_PARAMETER",
    0x80000002: "INVALID_HANDLE",
    0x80000003: "DEVICE_NOT_SUPPORTED",
    0x80000004: "INTERNAL_ERROR",
    0x80000005: "TIMEOUT",
    0x8000000F: "MORE_HEADER_DATA",
    0x80000010: "MORE_DATA",
    0x80000011: "INVALID_DATA",
    0x80000012: "INVALID_DATA_LENGTH",
    0x80000013: "INVALID_PACKET",
    0x80000016: "CRC_CHECKSUM",
    0x80000017: "CMD_CODE",
    0x80000018: "OUTOFMEMORY",
    0x80000105: "INVALID_NAME",
    0x80000106: "NOT_CONNECTED",
    0x80000107: "CANNOT_MAKE",
    0x80000108: "FILE_NOT_FOUND",
    0x80000109: "NOT_ENOUGH_QUOTA",
    0x8000010a: "ACCESS_DENIED",
    0x8000010c: "CANCELLED",
    0x8000010d: "CONNECTION_ABORTED",
    0x8000010e: "CONTINUE",
    0x8000010f: "GEN_FAILURE",
    0x80000110: "INCORRECT_ADDRESS",
    0x80000111: "INVALID_CATEGORY",
    0x80000112: "REQUEST_ABORTED",
    0x80000113: "RETRY",
    0x80000116: "DEVICE_NOT_AVAILABLE",
    0x80000201: "IDT_MISMATCH_MODELNAME",
    0x80000202: "IDT_DECOMPRES_FAILED",
    0x80000203: "IDT_INVALID_OPTION",
    0x80000204: "IDT_DECOMPRESS_END_FAILED",
    0x80000205: "IDT_DZ_HEADER",
    0x80000206: "IDT_RETRY_COUNT",
    0x80000207: "IDT_HEADER_SIZE",
    0x80000208: "IDT_TOT_MAGIC",
    0x80000209: "UDT_DZ_HEADER_SIZE",
    0x80000302: "INVALID_RESPONSE",
    0x80000305: "FAILED_INSERT_QUEUE",
    0x80000306: "FAILED_POP_QUEUE",
    0x80000307: "INVALID_LAF_PROTOCOL",
    0x80000308: "ERASE_FAILED",
    0x80000309: "WEBFLAG_RESET_FAIL",
    0x80000401: "FLASHING_FAIL",
    0x80000402: "SECURE_FAIL",
    0x80000403: "BUILD_TYPE_FAIL",
    0x80000404: "CHECK_USER_SPC",
    0x80000405: "FBOOT_CHECK_FAIL",
    0x80000406: "INIT_FAIL",
    0x80000407: "FRST_FLAG_FAIL",
    0x80000408: "POWER_OFF_FAIL",
    0x8000040a: "PRL_READ_FAIL",
    0x80000409: "PRL_WRITE_FAIL",
}

### USB or serial port communication


class Communication(object):
    def __init__(self):
        self.read_buffer = b''
        self.protocol_version = 0

    def read(self, n, timeout=None):
        """Reads exactly n bytes."""
        need = n - len(self.read_buffer)
        while need > 0:
            buff = self._read(need, timeout=timeout)
            self.read_buffer += buff
            if not buff:
                raise EOFError
            need -= len(buff)
        data, self.read_buffer = self.read_buffer[0:n], self.read_buffer[n:]
        return data

    def _read(self, n, timeout=None):
        """Try one read, possibly returning less or more than n bytes."""
        raise NotImplementedError

    def write(self, data):
        raise NotImplementedError

    def close(self):
        raise NotImplementedError

    def reset(self):
        self.read_buffer = b''

    def call(self, payload):
        """Sends a command and returns its response."""
        Lglaf.validate_message(payload)
        self.write(payload)
        header = self.read(0x20)
        Lglaf.validate_message(header, ignore_crc=True)
        cmd = header[0:4]
        size = struct.unpack_from('<I', header, 0x14)[0]
        # could validate CRC and inverted command here...
        data = self.read(size) if size else b''
        if cmd == b'FAIL':
            errCode = struct.unpack_from('<I', header, 4)[0]
            msg = 'LAF_ERROR_%s' % laf_error_codes.get(errCode, '<unknown>')
            raise RuntimeError('Command failed with error code %#x (%s)' % (errCode, msg))
        if cmd != payload[0:4]:
            raise RuntimeError("Unexpected response: %r" % header)
        return header, data


class FileCommunication(Communication):
    def __init__(self, file_path):
        super(FileCommunication, self).__init__()
        if sys.version_info[0] >= 3:
            self.f = open(file_path, 'r+b', buffering=0)
        else:
            self.f = open(file_path, 'r+b')

    def _read(self, n, timeout=None):
        return self.f.read(n)

    def write(self, data):
        self.f.write(data)

    def close(self):
        self.f.close()


class USBCommunication(Communication):
    VENDOR_ID_LG = 0x1004
    # Read timeout. Set to 0 to disable timeouts
    READ_TIMEOUT_MS = 60000

    def __init__(self):
        super(USBCommunication, self).__init__()
        # Match device using heuristics on the interface/endpoint descriptors,
        # this avoids hardcoding idProduct.
        self.usbdev = usb.core.find(idVendor=self.VENDOR_ID_LG,
                custom_match = self._match_device)
        if self.usbdev is None:
            raise RuntimeError("USB device not found")
        cfg = usb.util.find_descriptor(self.usbdev,
                custom_match=self._match_configuration)
        current_cfg = self.usbdev.get_active_configuration()
        if cfg.bConfigurationValue != current_cfg.bConfigurationValue:
            try:
                cfg.set()
            except usb.core.USBError as e:
                _logger.warning("Failed to set configuration, "
                        "has a kernel driver claimed the interface?")
                raise e
        for intf in cfg:
            if self.usbdev.is_kernel_driver_active(intf.bInterfaceNumber):
                _logger.debug("Detaching kernel driver for intf %d",
                        intf.bInterfaceNumber)
                self.usbdev.detach_kernel_driver(intf.bInterfaceNumber)
            if self._match_interface(intf):
                self._set_interface(intf)
        assert self.ep_in
        assert self.ep_out

    def _match_device(self, device):
        return any(
            usb.util.find_descriptor(cfg, custom_match=self._match_interface)
            for cfg in device
        )

    def _set_interface(self, intf):
        for ep in intf:
            ep_dir = usb.util.endpoint_direction(ep.bEndpointAddress)
            if ep_dir == usb.util.ENDPOINT_IN:
                self.ep_in = ep.bEndpointAddress
            else:
                self.ep_out = ep.bEndpointAddress
        _logger.debug("Using endpoints %02x (IN), %02x (OUT)",
                self.ep_in, self.ep_out)

    def _match_interface(self, intf):
        return intf.bInterfaceClass == 255 and \
            intf.bInterfaceSubClass == 255 and \
            intf.bInterfaceProtocol == 255 and \
            intf.bNumEndpoints == 2 and all(
            usb.util.endpoint_type(ep.bmAttributes) ==
                usb.util.ENDPOINT_TYPE_BULK
            for ep in intf
        )

    def _match_configuration(self, config):
        return usb.util.find_descriptor(config,
                custom_match=self._match_interface)

    def _read(self, n, timeout=None):
        if timeout is None:
            timeout = self.READ_TIMEOUT_MS
        # device seems to use 16 KiB buffers.
        array = self.usbdev.read(self.ep_in, 2**14, timeout=timeout)
        try: return array.tobytes()
        except: return array.tostring()

    def write(self, data):
        # Reset read buffer for response
        if self.read_buffer:
            _logger.warn('non-empty read buffer %r', self.read_buffer)
            self.read_buffer = b''
        self.usbdev.write(self.ep_out, data)

    def close(self):
        usb.util.dispose_resources(self.usbdev)


class Lglaf(object):
    """
    Protocol-related stuff
    """
    # Use Manufacturer key for KILO challenge/response
    USE_MFG_KEY = False
    # HELO command always sends BASE Protocol version
    BASE_PROTOCOL_VERSION = 0x1000001
    # Wait for at most 5 seconds for a response... it shouldn't take that long
    # and otherwise something is wrong.
    HELLO_READ_TIMEOUT = 5000

    def __init__(self, serial_path=None, rawshell=False, need_cr=False, block_size=512):
        assert block_size == 512 or block_size == 4096, "Invalid block size passed: %d" % block_size
        if serial_path:
            self._comm = FileCommunication(serial_path)
        else:
            self._comm = autodetect_device()
        self._rawshell = rawshell
        self._need_cr = need_cr
        self._block_size = block_size
        self._target_protocol_version = -1

    @property
    def comm(self):
        return self._comm

    @property
    def block_size(self):
        return self._block_size

    @property
    def target_protocol_version(self):
        return self._target_protocol_version

    @property
    def need_cr(self):
        return self._need_cr

    @staticmethod
    def make_request(cmd, args=[], body=b''):
        if not isinstance(cmd, bytes):
            cmd = cmd.encode('ascii')
        assert isinstance(body, bytes), "body must be bytes"

        # Header: command, args, ... body size, header crc16, inverted command
        header = bytearray(0x20)

        def set_header(offset, val):
            if isinstance(val, int):
                val = struct.pack('<I', val)
            assert len(val) == 4, "Header field requires a DWORD, got %s %r" % \
                    (type(val).__name__, val)
            header[offset:offset+4] = val

        set_header(0, cmd)
        assert len(args) <= 4, "Header cannot have more than 4 arguments"
        for i, arg in enumerate(args):
            set_header(4 * (i + 1), arg)

        # 0x14: body length
        set_header(0x14, len(body))
        # 0x1c: Inverted command
        set_header(0x1c, invert_dword(cmd))
        # Header finished (with CRC placeholder), append body...
        header += body
        # finish with CRC for header and body
        set_header(0x18, crc16(header))
        return bytes(header)


    @staticmethod
    def make_hdlc_request(body):
        assert isinstance(body, bytes), "body must be bytes"
        packet = bytearray(len(body) + 3)
        packet[0:] = body
        # Add CRC16 checksum (as uint16!)
        packet[len(body):] = struct.pack('<H', crc16(body))
        # Add terminator byte
        packet[-1:] = b'\x7F'
        return bytes(packet)


    @staticmethod
    def validate_message(payload, ignore_crc=False):
        if len(payload) < 0x20:
            raise RuntimeError("Invalid header length: %d" % len(payload))
        if not ignore_crc:
            crc = struct.unpack_from('<I', payload, 0x18)[0]
            payload_before_crc = bytearray(payload)
            payload_before_crc[0x18:0x18+4] = b'\0\0\0\0'
            crc_exp = crc16(payload_before_crc)
            if crc_exp != crc:
                raise RuntimeError("Expected CRC %04x, found %04x" % (crc_exp, crc))
        tail_exp = invert_dword(payload[0:4])
        tail = payload[0x1c:0x1c+4]
        if tail_exp != tail:
            raise RuntimeError("Expected trailer %r, found %r" % (tail_exp, tail))

    def make_exec_request(self, shell_command):
        """
        Allow use of shell constructs such as piping and reports syntax errors
        such as unterminated quotes. Remaining limitation: repetitive spaces are
        still eaten.
        If rawshell is set, execute the command as it's provided
        """
        if self._rawshell:
            argv = b''
        else:
            argv = b'sh -c eval\t"$*"</dev/null\t2>&1 -- '
        argv += shell_command.encode('ascii')
        if len(argv) > 255:
            raise RuntimeError("Command length %d is larger than 255" % len(argv))
        return Lglaf.make_request(b'EXEC', body=argv + b'\0')

    def make_hello_request(self, protocol_version=BASE_PROTOCOL_VERSION, mode=1):
        version_req = struct.pack("<I", protocol_version)
        return Lglaf.make_request(b'HELO', args=[version_req, 0, 0, mode])

    def make_kilo_request(self, subcmd, mode=0, body=b''):
        return Lglaf.make_request(b'KILO', args=[subcmd, 0, mode, 0], body=body)

    def make_open_request(self, filepath, body=b''):
        """
        Open requests for UFS have a yet unknown body
        """
        if isinstance(filepath, str):
            filepath = filepath.encode('ascii')
        if filepath[-1] != '\0':
            filepath += '\0'
        filepath += body
        return Lglaf.make_request(b'OPEN', body=filepath)

    def make_read_request(self, fd_num, offset, size):
        return Lglaf.make_request(b'READ', args=[fd_num, offset, size])

    def make_write_request(self, fd_num, offset, data, mode=0):
        return Lglaf.make_request(b'WRTE', args=[fd_num, offset, 0, mode], body=data)

    def make_erase_request(self, fd_num, sector_start, sector_count):
        return Lglaf.make_request(b'ERSE', args=[fd_num, sector_start, sector_count])

    def make_close_request(self, fd_num):
        return Lglaf.make_request(b'CLSE', args=[fd_num])

    def try_hello(self):
        """
        Tests whether the device speaks the expected protocol. If desynchronization
        is detected, tries to read as much data as possible.
        """
        hello_request = self.make_hello_request()
        self._comm.write(hello_request)
        data = self._comm.read(0x20, timeout=Lglaf.HELLO_READ_TIMEOUT)
        if data[0:4] != b'HELO':
            # Unexpected response, maybe some stale data from a previous execution?
            while data[0:4] != b'HELO':
                try:
                    Lglaf.validate_message(data, ignore_crc=True)
                    size = struct.unpack_from('<I', data, 0x14)[0]
                    self._comm.read(size, timeout=Lglaf.HELLO_READ_TIMEOUT)
                except RuntimeError:
                    pass
                # Flush read buffer
                self._comm.reset()
                data = self._comm.read(0x20, timeout=Lglaf.HELLO_READ_TIMEOUT)
            # Just to be sure, send another HELO request.
            self._comm.call(hello_request)
        # Assign received protocol version
        self._target_protocol_version = struct.unpack_from('<I', data, 0x4)[0]

    def challenge_response(self, mode):
        request_kilo = self.make_kilo_request(b'CENT')
        kilo_header, kilo_response = self._comm.call(request_kilo)
        kilo_challenge = kilo_header[8:12]
        _logger.debug("Challenge: %s" % binascii.hexlify(kilo_challenge))

        if self.USE_MFG_KEY:
            key = b'lgowvqnltpvtgogwswqn~n~mtjjjqxro'
        else:
            key = b'qndiakxxuiemdklseqid~a~niq,zjuxl'
        kilo_response = LafCrypto.encrypt_kilo_challenge(key, kilo_challenge)
        _logger.debug("Response: %s" % binascii.hexlify(kilo_response))

        kilo_metr_request = self.make_kilo_request(b'METR', mode, bytes(kilo_response))
        metr_header, metr_response = self._comm.call(kilo_metr_request)
        _logger.debug("KILO METR Response -> Header: %s, Body: %s" % (
            binascii.hexlify(metr_header), binascii.hexlify(metr_response)))

    def command_to_payload(self, command):
        """
        Handle '!' as special commands, treat others as shell command
        
        !command [arg1[,arg2[,arg3[,arg4]]]] [body]
        args are treated as integers (decimal or hex)
        body is treated as string (escape sequences are supported)
        """
        if command[0] != '!':
            return self.make_exec_request(command)

        command = command[1:]
        command, args, body = (command.split(' ', 2) + ['', ''])[0:3]
        command = text_unescape(command)
        args = list(map(parse_number_or_escape, args.split(',') + [0, 0, 0]))[0:4]
        body = text_unescape(body)
        return self.make_request(command, args, body)


def detect_serial_path():
    try:
        path = r'HARDWARE\DEVICEMAP\SERIALCOMM'
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            for i in range(winreg.QueryInfoKey(key)[1]):
                name, value, value_type = winreg.EnumValue(key, i)
                # match both \Device\LGANDNETDIAG1 and \Device\LGVZANDNETDIAG1
                name = name.upper()
                if name.startswith(r'\DEVICE\LG') and name.endswith('ANDNETDIAG1'):
                    return value
    except OSError: pass
    return None


def autodetect_device():
    if winreg is not None and 'usb.core' not in sys.modules:
        serial_path = detect_serial_path()
        _logger.debug("Using serial port: %s", serial_path)
        if not serial_path:
            raise RuntimeError("Device not found, try installing LG drivers")
        return FileCommunication(serial_path)
    else:
        if 'usb.core' not in sys.modules:
            raise RuntimeError("Please install PyUSB for USB support")
        return USBCommunication()



### Interactive loop

def get_commands(command):
    if command:
        yield command
        return
    # Happened on Win32/Py3.4.4 when: echo ls | lglaf.py --serial com4
    if sys.stdin is None:
        raise RuntimeError('No console input available!')
    if sys.stdin.isatty():
        print("LGLAF.py by Peter Wu (https://lekensteyn.nl/lglaf)\n"
                "Type a shell command to execute or \"exit\" to leave.",
                file=sys.stderr)
        prompt = '# '
    else:
        prompt = ''
    try:
        while True:
            line = input(prompt)
            if line == "exit":
                break
            if line:
                yield line
    except EOFError:
        if prompt:
            print("", file=sys.stderr)


parser = argparse.ArgumentParser(description='LG LAF Download Mode utility')
parser.add_argument("-c", "--command", help='Shell command to execute')
parser.add_argument("--rawshell", help='Execute commands as-is, no redirection for stderr')
parser.add_argument("--cr", help='Device needs challenge/response')
parser.add_argument("--ufs", help='Treat target device with UFS partitioning')
parser.add_argument("--serial", metavar="PATH", dest="serial_path",
        help="Path to serial device (e.g. COM4).")
parser.add_argument("--debug", action='store_true', help="Enable debug messages")

def main():
    args = parser.parse_args()
    logging.basicConfig(format='%(name)s: %(levelname)s: %(message)s',
            level=logging.DEBUG if args.debug else logging.INFO)

    # Binary stdout (output data from device as-is)
    try: stdout_bin = sys.stdout.buffer
    except: stdout_bin = sys.stdout

    block_size = 512 if not args.ufs else 4096
    lglaf = Lglaf(args.serial_path, args.rawshell, args.cr, block_size)

    with closing(lglaf.comm):
        lglaf.try_hello()
        _logger.debug("Using Protocol version: 0x%x" % lglaf.target_protocol_version)
        _logger.debug("Hello done, proceeding with commands")
        for command in get_commands(args.command):
            try:
                payload = lglaf.command_to_payload(command)

                if lglaf.need_cr:
                    if payload[0:4] in [b'UNLK', b'OPEN', b'EXEC']:
                        lglaf.challenge_response(2)
                    elif payload[0:4] == b'CLSE':
                        lglaf.challenge_response(4)
                header, response = lglaf.comm.call(payload)

                # For debugging, print header
                if command[0] == '!':
                    _logger.debug('Header: %s',
                                  ' '.join(repr(header[i:i+4]).replace("\\x00", "\\0")
                        for i in range(0, len(header), 4)))
                stdout_bin.write(response)
            except Exception as e:
                _logger.warn(e)
                if args.debug:
                    import traceback; traceback.print_exc()

if __name__ == '__main__':
    main()
