__author__ = 'Roee'

import socket
import dns
import dns.name
import dns.rdatatype
import dns.rdataclass
import dns.message
import dns.query
import dns.exception


class DnsFacilities:
    def __init__(self):
        raise NotImplementedError

    @staticmethod
    def send_query(sock, q, open_resolver_address):
        sock.sendto(q.to_wire(), (open_resolver_address, 53))

    @staticmethod
    def read_response(sock):
        (wire, from_address) = sock.recvfrom(1024)

        try:
            return dns.message.from_wire(wire), from_address
        except (socket.error, dns.exception.Timeout):
            pass
        except dns.query.UnexpectedSource:
            pass
        except dns.exception.FormError:
            pass
        except ValueError:
            #ValueError: IPv6 addresses are 16 bytes long
            pass
        except EOFError:
            pass
        return None, from_address

    @staticmethod
    def build_query(qname, recursion_desired=True, rdtype='A', rdclass='IN'):
        # Adjust parameters
        if isinstance(qname, (str, unicode)):
            qname = dns.name.from_text(qname, None)
        if isinstance(rdtype, (str, unicode)):
            rdtype = dns.rdatatype.from_text(rdtype)
        if dns.rdatatype.is_metatype(rdtype):
            raise dns.NoMetaqueries
        if isinstance(rdclass, (str, unicode)):
            rdclass = dns.rdataclass.from_text(rdclass)
        if dns.rdataclass.is_metaclass(rdclass):
            raise dns.NoMetaqueries

        if not qname.is_absolute():
            qname = qname.concatenate(dns.name.root)

        # Build request
        request = dns.message.make_query(qname, rdtype, rdclass)
        if not recursion_desired:
            request.flags ^= dns.flags.RD

        return request

    @staticmethod
    def generate_domain_to_query(domain, open_resolver_address):
        return open_resolver_address + domain
