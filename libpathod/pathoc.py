import sys
import os
import hashlib
import random
from netlib import tcp, http, certutils
import netlib.utils

from . import language
from . import utils
import OpenSSL.crypto


class PathocError(Exception):
    pass


class SSLInfo:
    def __init__(self, certchain, cipher):
        self.certchain, self.cipher = certchain, cipher


class Response:
    def __init__(
        self,
        httpversion,
        status_code,
        msg,
        headers,
        content,
        sslinfo
    ):
        self.httpversion, self.status_code = httpversion, status_code
        self.msg = msg
        self.headers, self.content = headers, content
        self.sslinfo = sslinfo

    def __repr__(self):
        return "Response(%s - %s)"%(self.status_code, self.msg)


class Pathoc(tcp.TCPClient):
    def __init__(
            self,
            address,
            ssl=None,
            sni=None,
            sslversion=4,
            clientcert=None,
            ciphers=None):
        tcp.TCPClient.__init__(self, address)
        self.settings = dict(
            staticdir = os.getcwd(),
            unconstrained_file_access = True,
        )
        self.ssl, self.sni = ssl, sni
        self.clientcert = clientcert
        self.sslversion = utils.SSLVERSIONS[sslversion]
        self.ciphers = ciphers

    def http_connect(self, connect_to):
        self.wfile.write(
            'CONNECT %s:%s HTTP/1.1\r\n'%tuple(connect_to) +
            '\r\n'
        )
        self.wfile.flush()
        l = self.rfile.readline()
        if not l:
            raise PathocError("Proxy CONNECT failed")
        parsed = http.parse_response_line(l)
        if not parsed[1] == 200:
            raise PathocError("Proxy CONNECT failed: %s - %s"%(parsed[1], parsed[2]))
        http.read_headers(self.rfile)

    def connect(self, connect_to=None):
        """
            connect_to: A (host, port) tuple, which will be connected to with an
            HTTP CONNECT request.
        """
        tcp.TCPClient.connect(self)
        if connect_to:
            self.http_connect(connect_to)
        self.sslinfo = None
        if self.ssl:
            try:
                self.convert_to_ssl(
                    sni=self.sni,
                    cert=self.clientcert,
                    method=self.sslversion,
                    cipher_list = self.ciphers
                )
            except tcp.NetLibError as v:
                raise PathocError(str(v))
            self.sslinfo = SSLInfo(
                self.connection.get_peer_cert_chain(),
                self.get_current_cipher()
            )

    def request(self, spec):
        """
            Return an (httpversion, code, msg, headers, content) tuple.

            May raise language.ParseException, netlib.http.HttpError or
            language.FileAccessDenied.
        """
        r = language.parse_requests(spec)[0]
        language.serve(r, self.wfile, self.settings, self.address.host)
        self.wfile.flush()
        ret = list(http.read_response(self.rfile, r.method.string(), None))
        ret.append(self.sslinfo)
        return Response(*ret)

    def _show_summary(self, fp, httpversion, code, msg, headers, content):
        print("<< %s %s: %s bytes"%(
            code, utils.xrepr(msg), len(content)
        ), file=fp)

    def _show(self, fp, header, data, hexdump):
        if hexdump:
            print("%s (hex dump):"%header, file=fp)
            for line in netlib.utils.hexdump(data):
                print("\t%s %s %s"%line, file=fp)
        else:
            print("%s (unprintables escaped):"%header, file=fp)
            print(netlib.utils.cleanBin(data), file=fp)

    def print_request(
        self,
        r,
        showreq,
        showresp,
        explain,
        showssl,
        hexdump,
        ignorecodes,
        ignoretimeout,
        fp=sys.stdout
    ):
        """
            Performs a series of requests, and prints results to the specified
            file descriptor.

            spec: A request specification
            showreq: Print requests
            showresp: Print responses
            explain: Print request explanation
            showssl: Print info on SSL connection
            hexdump: When printing requests or responses, use hex dump output
            ignorecodes: Sequence of return codes to ignore

            Returns True if we have a non-ignored response.
        """
        resp, req = None, None
        if showreq:
            self.wfile.start_log()
        if showresp:
            self.rfile.start_log()
        try:
            req = language.serve(
                r,
                self.wfile,
                self.settings,
                self.address.host
            )
            self.wfile.flush()
            resp = http.read_response(self.rfile, r.method.string(), None)
        except http.HttpError as v:
            print("<< HTTP Error:", v.message, file=fp)
        except tcp.NetLibTimeout:
            if ignoretimeout:
                return
            print("<<", "Timeout", file=fp)
        except tcp.NetLibDisconnect: # pragma: nocover
            print("<<", "Disconnect", file=fp)

        if req:
            if ignorecodes and resp and resp[1] in ignorecodes:
                return

            if explain:
                print(">> Spec:", r.spec(), file=fp)

            if showreq:
                self._show(fp, ">> Request", self.wfile.get_log(), hexdump)

            if showresp:
                self._show(fp, "<< Response", self.rfile.get_log(), hexdump)
            else:
                if resp:
                    self._show_summary(fp, *resp)

            if showssl and self.sslinfo:
                print("Cipher: %s, %s bit, %s"%self.sslinfo.cipher, file=fp)
                print("SSL certificate chain:\n", file=fp)
                for i in self.sslinfo.certchain:
                    print("\tSubject: ", end=' ', file=fp)
                    for cn in i.get_subject().get_components():
                        print("%s=%s"%cn, end=' ', file=fp)
                    print(file=fp)
                    print("\tIssuer: ", end=' ', file=fp)
                    for cn in i.get_issuer().get_components():
                        print("%s=%s"%cn, end=' ', file=fp)
                    print(file=fp)
                    print("\tVersion: %s"%i.get_version(), file=fp)
                    print("\tValidity: %s - %s"%(
                        i.get_notBefore(), i.get_notAfter()
                    ), file=fp)
                    print("\tSerial: %s"%i.get_serial_number(), file=fp)
                    print("\tAlgorithm: %s"%i.get_signature_algorithm(), file=fp)
                    pk = i.get_pubkey()
                    types = {
                        OpenSSL.crypto.TYPE_RSA: "RSA",
                        OpenSSL.crypto.TYPE_DSA: "DSA"
                    }
                    t = types.get(pk.type(), "Uknown")
                    print("\tPubkey: %s bit %s"%(pk.bits(), t), file=fp)
                    s = certutils.SSLCert(i)
                    if s.altnames:
                        print("\tSANs:", " ".join(s.altnames), file=fp)
                    print(file=fp)
            return True


def main(args):
    memo = set([])
    trycount = 0
    try:
        cnt = 0
        while 1:
            if trycount > args.memolimit:
                print("Memo limit exceeded...", file=sys.stderr)
                return

            cnt += 1
            if args.random:
                playlist = [random.choice(args.requests)]
            else:
                playlist = args.requests
            p = Pathoc(
                (args.host, args.port),
                ssl=args.ssl,
                sni=args.sni,
                sslversion=args.sslversion,
                clientcert=args.clientcert,
                ciphers=args.ciphers
            )
            if args.explain or args.memo:
                playlist = [
                    i.freeze(p.settings, p.address.host) for i in playlist
                ]
            if args.memo:
                newlist = []
                for spec in playlist:
                    h = hashlib.sha256(spec.spec()).digest()
                    if h not in memo:
                        memo.add(h)
                        newlist.append(spec)
                playlist = newlist
            if not playlist:
                trycount += 1
                continue

            trycount = 0
            try:
                p.connect(args.connect_to)
            except (tcp.NetLibError, PathocError) as v:
                print(str(v), file=sys.stderr)
                sys.exit(1)
            if args.timeout:
                p.settimeout(args.timeout)
            for spec in playlist:
                ret = p.print_request(
                    spec,
                    showreq=args.showreq,
                    showresp=args.showresp,
                    explain=args.explain,
                    showssl=args.showssl,
                    hexdump=args.hexdump,
                    ignorecodes=args.ignorecodes,
                    ignoretimeout=args.ignoretimeout
                )
                sys.stdout.flush()
                if ret and args.oneshot:
                    sys.exit(0)
            if cnt == args.repeat:
                break
    except KeyboardInterrupt:
        pass
