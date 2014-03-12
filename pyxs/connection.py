# -*- coding: utf-8 -*-
"""
    pyxs.connection
    ~~~~~~~~~~~~~~~

    This module implements two connection backends for
    :class:`~pyxs.client.Client`.

    :copyright: (c) 2011 by Selectel, see AUTHORS for more details.
    :license: LGPL, see LICENSE for more details.
"""

from __future__ import absolute_import, unicode_literals

__all__ = ["UnixSocketConnection", "XenBusConnection", "XenBusConnectionWin"]

import errno
import os
import platform
import socket
import sys

if os.name in ["nt"]:
    import ctypes
    from ctypes.wintypes import HANDLE
    from ctypes.wintypes import BOOL
    from ctypes.wintypes import HWND
    from ctypes.wintypes import DWORD
    from ctypes.wintypes import WORD
    from ctypes.wintypes import LONG
    from ctypes.wintypes import ULONG
    from ctypes.wintypes import LPCSTR
    from ctypes.wintypes import HKEY
    from ctypes.wintypes import BYTE

if sys.version_info[0] is not 3:
    bytes, str = str, unicode

from .exceptions import ConnectionError, WindowsDriverError
from .helpers import writeall, readall, osnmopen, osnmclose, osnmread
from ._internal import Packet


class FileDescriptorConnection(object):
    """Abstract XenStore connection, using an fd for I/O operations.

    Subclasses are expected to define :meth:`connect()` and set
    :attr:`fd` and :attr:`path` attributes, where `path` is a human
    readable path to the object, `fd` points to.
    """
    fd = path = None

    def __init__(self):
        raise NotImplemented("__init__() should be overridden by subclasses.")

    def disconnect(self, silent=True):
        """Disconnects from XenStore.

        :param bool silent: if ``True`` (default), any errors, raised
                            while closing the file descriptor are
                            suppressed.
        """
        if self.fd is None:
            return

        try:
            osnmclose(self.fd)
        except OSError as e:
            if not silent:
                raise ConnectionError(e.args)
        finally:
            self.fd = None

    def send(self, packet):
        """Sends a given packet to XenStore.

        :param pyxs._internal.Packet packet: a packet to send, is
            expected to be validated, since no checks are done at
            that point.
        """
        if not self.fd:
            self.connect()

        # Note the ``[:-1]`` slice -- the actual payload is excluded.
        data = (packet._struct.pack(*packet[:-1]) +
                packet.payload.encode("utf-8"))

        try:
            writeall(self.fd, data)
        except OSError as e:
            if e.args[0] in [errno.ECONNRESET,
                             errno.ECONNABORTED,
                             errno.EPIPE]:
                self.disconnect()

            raise ConnectionError("Error while writing to {0!r}: {1}"
                                  .format(self.path, e.args))

    def recv(self):
        """Receives a packet from XenStore."""
        if not self.fd:
            self.connect()

        try:
            header = readall(self.fd, Packet._struct.size)
        except OSError as e:
            if e.args[0] in [errno.ECONNRESET,
                             errno.ECONNABORTED,
                             errno.EPIPE]:
                self.disconnect()

            raise ConnectionError("Error while reading from {0!r}: {1}"
                                  .format(self.path, e.args))
        else:
            op, rq_id, tx_id, size = Packet._struct.unpack(header)

            # XXX XenBus seems to handle ``os.read(fd, 0)`` incorrectly,
            # blocking unless any new data appears, so we have to check
            # size value, before reading.
            payload = ("" if size is 0 else
                       osnmread(self.fd, size).decode("utf-8"))

            return Packet(op, payload, rq_id, tx_id)


class UnixSocketConnection(FileDescriptorConnection):
    """XenStore connection through Unix domain socket.

    :param str path: path to XenStore unix domain socket, if not
                     provided explicitly is restored from process
                     environment -- similar to what ``libxs`` does.
    :param float socket_timeout: see :func:`~socket.socket.settimeout`
                                 for details.
    """
    def __init__(self, path=None, socket_timeout=None):
        if path is None:
            path = (
                os.getenv("XENSTORED_PATH") or
                os.path.join(os.getenv("XENSTORED_RUNDIR",
                                       "/var/run/xenstored"), "socket")
            )

        self.path = path
        self.socket_timeout = socket_timeout

    def __copy__(self):
        return self.__class__(self.path, self.socket_timeout)

    def connect(self):
        if self.fd:
            return

        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            if self.socket_timeout is not None:
                sock.settimeout(self.socket_timeout)
            sock.connect(self.path)
        except socket.error as e:
            raise ConnectionError("Error connecting to {0!r}: {1}"
                                  .format(self.path, e.args))
        else:
            self.fd = os.dup(sock.fileno())


class XenBusConnection(FileDescriptorConnection):
    """XenStore connection through XenBus.

    :param str path: path to XenBus block device; a predefined
                     OS-specific constant is used, if a value isn't
                     provided explicitly.
    """
    def __init__(self, path=None):
        if path is None:
            # .. note:: it looks like OCaml-powered ``xenstored``
            # simply ignores the possibility of being launched on a
            # platform, different from Linux, but ``libxs``  has those
            # constants in-place.
            system = platform.system()

            if system == "Linux":
                path = "/proc/xen/xenbus"
            elif system == "NetBSD":
                path = "/kern/xen/xenbus"
            else:
                path = "/dev/xen/xenbus"

        self.path = path

    def __copy__(self):
        return self.__class__(self.path)

    def connect(self):
        if self.fd:
            return

        try:
            self.fd = osnmopen(self.path, os.O_RDWR)
        except OSError as e:
            raise ConnectionError("Error while opening {0!r}: {1}"
                                  .format(self.path, e.args))


class XenBusConnectionWin(FileDescriptorConnection):
    def __init__(self):
        # Determine self.path using some magic Windows code which is derived from
        # http://pydoc.net/Python/pyserial/2.6/serial.tools.list_ports_windows/.
        # The equivalent C from The GPLPV driver source can be found in get_xen_interface_path() of shutdownmon.
        # - http://xenbits.xensource.com/ext/win-pvdrivers/file/896402519f15/shutdownmon/shutdownmon.c
        DIGCF_PRESENT = 2
        DIGCF_DEVICEINTERFACE = 16
        NULL = None
        ERROR_SUCCESS = 0
        ERROR_INSUFFICIENT_BUFFER = 122
        ERROR_NO_MORE_ITEMS = 259

        HDEVINFO = ctypes.c_void_p
        PCTSTR = ctypes.c_char_p
        CHAR = ctypes.c_char
        PDWORD = ctypes.POINTER(DWORD)
        LPDWORD = ctypes.POINTER(DWORD)
        PULONG = ctypes.POINTER(ULONG)

        # Return code checkers
        def ValidHandle(value, func, arguments):
            if value == 0:
                raise WindowsDriverError(str(ctypes.WinError()))
            return value

        # Some structures used by the Windows API
        class GUID(ctypes.Structure):
            _fields_ = [
                ('Data1', DWORD),
                ('Data2', WORD),
                ('Data3', WORD),
                ('Data4', BYTE*8),
            ]

            def __str__(self):
                return "{%08x-%04x-%04x-%s-%s}" % (
                    self.Data1,
                    self.Data2,
                    self.Data3,
                    ''.join(["%02x" % d for d in self.Data4[:2]]),
                    ''.join(["%02x" % d for d in self.Data4[2:]]),
                )

        class SP_DEVINFO_DATA(ctypes.Structure):
            _fields_ = [
                ('cbSize', DWORD),
                ('ClassGuid', GUID),
                ('DevInst', DWORD),
                ('Reserved', PULONG),
            ]

            def __str__(self):
                return "ClassGuid:%s DevInst:%s" % (self.ClassGuid, self.DevInst)
        PSP_DEVINFO_DATA = ctypes.POINTER(SP_DEVINFO_DATA)

        class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
            _fields_ = [
                ('cbSize', DWORD),
                ('InterfaceClassGuid', GUID),
                ('Flags', DWORD),
                ('Reserved', PULONG),
            ]

            def __str__(self):
                return "InterfaceClassGuid:%s Flags:%s" % (self.InterfaceClassGuid, self.Flags)
        PSP_DEVICE_INTERFACE_DATA = ctypes.POINTER(SP_DEVICE_INTERFACE_DATA)

        PSP_DEVICE_INTERFACE_DETAIL_DATA = ctypes.c_void_p

        # Import the Windows APIs
        setupapi = ctypes.windll.LoadLibrary("setupapi")

        SetupDiGetClassDevs = setupapi.SetupDiGetClassDevsA
        SetupDiGetClassDevs.argtypes = [ctypes.POINTER(GUID), PCTSTR, HWND, DWORD]
        SetupDiGetClassDevs.restype = HDEVINFO
        SetupDiGetClassDevs.errcheck = ValidHandle

        SetupDiEnumDeviceInterfaces = setupapi.SetupDiEnumDeviceInterfaces
        SetupDiEnumDeviceInterfaces.argtypes = [HDEVINFO, PSP_DEVINFO_DATA, ctypes.POINTER(GUID), DWORD, PSP_DEVICE_INTERFACE_DATA]
        SetupDiEnumDeviceInterfaces.restype = BOOL

        SetupDiGetDeviceInterfaceDetail = setupapi.SetupDiGetDeviceInterfaceDetailA
        SetupDiGetDeviceInterfaceDetail.argtypes = [HDEVINFO, PSP_DEVICE_INTERFACE_DATA, PSP_DEVICE_INTERFACE_DETAIL_DATA, DWORD, PDWORD, PSP_DEVINFO_DATA]
        SetupDiGetDeviceInterfaceDetail.restype = BOOL

        SetupDiDestroyDeviceInfoList = setupapi.SetupDiDestroyDeviceInfoList
        SetupDiDestroyDeviceInfoList.argtypes = [HDEVINFO]
        SetupDiDestroyDeviceInfoList.restype = BOOL

        # Do stuff
        GUID_XENBUS_IFACE = GUID(0x14ce175aL, 0x3ee2, 0x4fae, (BYTE*8)(0x92, 0x52, 0x0, 0xdb, 0xd8, 0x4f, 0x1, 0x8e))

        handle = SetupDiGetClassDevs(ctypes.byref(GUID_XENBUS_IFACE), NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

        sdid = SP_DEVICE_INTERFACE_DATA()
        sdid.cbSize = ctypes.sizeof(sdid)
        if not SetupDiEnumDeviceInterfaces(handle, NULL, ctypes.byref(GUID_XENBUS_IFACE), 0, ctypes.byref(sdid)):
            if ctypes.GetLastError() != ERROR_NO_MORE_ITEMS:
                    raise WindowsDriverError(str(ctypes.WinError()))

        buf_len = DWORD()
        if not SetupDiGetDeviceInterfaceDetail(handle, ctypes.byref(sdid), NULL, 0, ctypes.byref(buf_len), NULL):
            if ctypes.GetLastError() != ERROR_INSUFFICIENT_BUFFER:
                raise WindowsDriverError(str(ctypes.WinError()))

        # We didn't know how big to make the structure until buf_len is assigned...
        class SP_DEVICE_INTERFACE_DETAIL_DATA_A(ctypes.Structure):
            _fields_ = [
                ('cbSize', DWORD),
                ('DevicePath', CHAR*(buf_len.value - ctypes.sizeof(DWORD))),
            ]

            def __str__(self):
                return "DevicePath:%s" % (self.DevicePath,)

        sdidd = SP_DEVICE_INTERFACE_DETAIL_DATA_A()
        sdidd.cbSize = ctypes.sizeof(ctypes.POINTER(SP_DEVICE_INTERFACE_DETAIL_DATA_A))
        if not SetupDiGetDeviceInterfaceDetail(handle, ctypes.byref(sdid), ctypes.byref(sdidd), buf_len, NULL, NULL):
            raise WindowsDriverError(str(ctypes.WinError()))
        self.path = ""+sdidd.DevicePath

        SetupDiDestroyDeviceInfoList(handle)


    def __copy__(self):
        return self.__class__()


    def connect(self):
        if self.fd:
            return

        try:
             self.fd = osnmopen(self.path)
        except Exception as e:
             raise ConnectionError("Error while opening {0!r}: {1}"
                                  .format(self.path, e.args))
