import socket
import struct
import os
import logging

from contextlib import closing
from enum import IntEnum

try:
    import gdb
except ImportError:
    pass


class ReqType(IntEnum):
    INVALID   = 2
    NONE      = 3
    ADD       = 4
    GETPRIV   = 5
    SETPRIV   = 6
    GET       = 7
    STORE     = 8
    LOAD      = 9
    MAX       = 10


class VulnSrvAPI:
    """
    Wrapper for sending/receiving requests from the vuln_srv.
    """

    # Mapping for C types to 'struct' module format strings
    C_TYPE_MAPPING = {'int': 'i', '*': 'I'}

    def __init__(self, port, gdb):
        self.port = port
        self.gdb = gdb
        self.logger = logging.getLogger(__name__)

        self._var_t__c_type = VulnSrvAPI.C_TYPE_MAPPING['int']
        self._g_struct_p_t__c_type = VulnSrvAPI.C_TYPE_MAPPING['*']
        self._g_var_p_t__c_type = VulnSrvAPI.C_TYPE_MAPPING['*']

        if gdb:
            self._gdb_preprocess()

    ##--- GDB Processing --##
    @staticmethod
    def _is_ptr(typename):
        return '*' if '*' in typename.name else typename.name

    def _gdb_preprocess(self):
        filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_srv')
        gdb.execute('file ' + filepath)
        var_t = gdb.lookup_type('var_t')
        self._var_t__c_type = VulnSrvAPI.C_TYPE_MAPPING[VulnSrvAPI._is_ptr(
            var_t.strip_typedefs())]

    ##--- API Definitions ---##
    def send(self, type_, size, climit=None, p_srv=None, p_g_d=None):
        """
        Connect to vulnerable server, send request and receive a response.
        """
        bin_type = struct.Struct(self._var_t__c_type).pack(type_)
        bin_size = struct.Struct(self._var_t__c_type).pack(size)

        bin_climit = '' if climit is None else struct.Struct(
            self._var_t__c_type).pack(climit)

        if p_srv is not None and p_srv < 0:
            p_srv += 2**32

        if p_g_d is not None and p_g_d < 0:
            p_g_d += 2**32

        bin_p_srv = '' if p_srv is None else struct.Struct(
            self._g_struct_p_t__c_type).pack(p_srv)
        bin_p_g_d = '' if p_g_d is None else struct.Struct(
            self._g_var_p_t__c_type).pack(p_g_d)

        bin_padding = struct.pack(self._var_t__c_type * 3, 0, 0, 0)

        pdata = bin_type + bin_size + bin_padding

        if bin_climit:
            pdata += bin_climit
            if bin_p_srv:
                pdata += bin_p_srv
                if bin_p_g_d:
                    pdata += bin_p_g_d

        with closing(socket.socket()) as sock:
            host = socket.gethostname()
            sock.connect((host, self.port))
            sock.send(pdata)
            return sock.recv(32)

    def send_none(self):
        self.send(ReqType.NONE, 0)

    def send_add(self, val, dst=None):
        climit = None

        if dst:
            self.logger.debug('add - dst: %s, val: %s' % (hex(dst), hex(val)))
            climit = 1024

        self.send(type_=ReqType.ADD, size=val, climit=climit, p_srv=dst)

    def send_getpriv(self):
        resp = self.send(ReqType.GETPRIV, 0)
        resp_d = resp.decode('utf-8').replace('\0', '').strip().split(':')[1]
        return resp_d

    def send_setpriv(self, priv):
        resp = self.send(ReqType.SETPRIV, priv)
        resp_d = resp.decode('utf-8').replace('\0', '').strip().split(':')[1]
        return resp_d

    def send_get(self):
        resp = self.send(ReqType.GET, 0)
        resp_d = resp.decode().replace('\0', '').strip().split(':')[1]
        return int(resp_d, 16)

    def send_store(self, src=None, dst=None):
        climit = None

        if src and dst:
            self.logger.debug('store - src: %s, dst: %s' % (hex(src), hex(dst)))
            climit = 1024

        self.send(
            type_=ReqType.STORE, size=0, climit=climit, p_srv=dst, p_g_d=src)

    def send_load(self, src=None, dst=None):
        climit = None

        if src and dst:
            self.logger.debug('load - src: %s, dst: %s' % (hex(src), hex(dst)))
            climit = 1024
        self.send(
            type_=ReqType.LOAD, size=0, climit=climit, p_srv=src, p_g_d=dst)

    def send_assign(self, val, dst=None):
        climit = None
        if dst:
            self.logger.debug('assign - dst: %s, val: %s' % (hex(dst), hex(val)))
            climit = 1024
        self.send(type_=ReqType.MAX, size=val, climit=climit, p_srv=dst)


def complete_code_coverage(vuln_srv):
    vuln_srv.send_add(0)
    vuln_srv.send_getpriv()
    vuln_srv.send_setpriv(0)
    vuln_srv.send_setpriv(0x1337)
    vuln_srv.send_getpriv()
    vuln_srv.send_get()
    vuln_srv.send_store()
    vuln_srv.send_load()
    vuln_srv.send_assign(0)
    vuln_srv.send(ReqType.INVALID, 0)
    vuln_srv.send_none()
