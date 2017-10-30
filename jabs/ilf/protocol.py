'''
Ip4Protocol - wrapper around data.IP4PROTOCOLS
'''

class Ip4Protocol(object):
    'helper to translate strings to port,protocol nrs'
    ip4_proto_json = 'ip4-protocols.json'
    ip4_services_json = 'ip4-services.json'

    def __init__(self, load_services=False):
        self._num_toname = {}       # e.g. 6 -> 'tcp'
        self._num_todesc = {}       # e.g. 6 -> 'Transmission Control'
        self._name_tonum = {}       # e.e. 'tcp' -> 6
        self._service_toports = {}  # e.g https -> ['443/tcp', '443/udp']
        self._port_toservice = {}   # 'port/proto'     -> ip4-service-name


        # the json files are data files produced for ipf.py by updta.py
        self.load_protos('ip4-protocols.json')
        if load_services:
            self.load_services('ip4-services.json')

    def load_protos(self, filename):
        'read json encoded ip4-protocol information'
        # {'6': ['tcp', 'Transmission Control'], ..}

        altname = os.path.join(os.path.dirname(__file__), filename)
        altname = os.path.expanduser(altname)
        fname = filename if os.path.exists(filename) else altname

        try:
            with open(fname, 'r') as fh:
                dct = json.load(fh)
        except (OSError, IOError) as e:
            raise IOError('Cannot read {!r} or {!r}: {!r}'.format(filename,
                                                                  altname, e))

        self._num_toname = dict((int(k), v[0].lower()) for k, v in dct.items())
        self._num_todesc = dict((int(k), v[1]) for k, v in dct.items())
        self._name_tonum = dict((v[0].lower(), int(k)) for k, v in dct.items())

    def load_services(self, filename):
        'load ipv4-services from file created by updta.py'
        # {"995/udp": "pop3s", ..}

        altname = os.path.join(os.path.dirname(__file__), filename)
        altname = os.path.expanduser(altname)
        fname = filename if os.path.exists(filename) else altname

        try:
            with open(fname, 'r') as fh:
                dct = json.load(fh)
        except (OSError, IOError) as e:
            raise IOError('cannot read {!r} or {!r}: {!r}'.format(filename,
                                                                  altname, e))

        self._port_toservice = dct
        self._service_toports.clear()
        for port, service in dct.items():
            self._service_toports.setdefault(service, []).append(port)

        return self

    def proto_byname(self, name):
        'turn protocol name into its ip protocol number'
        err = 'invalid ipv4 protocol name: {!r}'
        rv = self._name_tonum.get(name.lower(), None)
        if rv is None:
            raise ValueError(err.format(name))
        return rv

    def proto_toname(self, num):
        'turn ipv4 protocol number into its name'
        err = 'invalid ipv4 protocol number {}'
        rv = self._num_toname.get(num, None)
        if rv is None:
            raise ValueError(err.format(num))
        return rv

    def service_toports(self, name):
        'turn service name into a list of port strings'
        err = 'unknown service name {!r}'
        rv = self._service_toports(name.lower(), None)
        if rv is None:
            raise ValueError(err.format(name))
        return rv

    def service_byport(self, portstr):
        'turn port string into its associated service name'
        err = 'invalid ipv4 protocol port string'
        rv = self._port_toservice.get(portstr.lower(), '')
        return rv


    def set_service(self, service, portstrings):
        'set known ports for a service, eg http->[80/tcp]'
        # TODO: check validity, remove spaces etc ...
        self._service_toports[service.lower()] = [x.lower() for x in
                                                  portstrings]
