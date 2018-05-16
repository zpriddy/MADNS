# Taken from https://gist.github.com/andreif/6069838

# coding=utf-8
"""
LICENSE http://www.apache.org/licenses/LICENSE-2.0
"""
import datetime
import sys
import time
import threading
import traceback
import socketserver
import requests
from dnslib import *
from dns import resolver
from pymongo import MongoClient
import tldextract


client = MongoClient()
db = client.madns
collection = db.whitelist

class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)

def DNSOverride(domain, queryType):
    r = resolver.Resolver()
    r.nameservers = ['8.8.8.8','8.8.4.4']
    a = r.query(domain, queryType)
    return a

def checkWitelist(domain):
    print('Looking for domain: %s' % domain)
    ed = tldextract.extract(domain)
    rootDomain = "{}.{}".format(ed.domain, ed.suffix)
    d = collection.find_one({"domain": rootDomain})
    if d is not None:
        if "*" in d.get('rules') or ed.subdomain in d.get('rules'):
            return True
    return False




D = DomainName('z.com')
IP = '127.0.0.1'
TTL = 60 * 5
PORT = 53

soa_record = SOA(
    mname=D.ns1,  # primary name server
    rname=D.andrei,  # email of the domain administrator
    times=(
        201307231,  # serial number
        60 * 60 * 1,  # refresh
        60 * 60 * 3,  # retry
        60 * 60 * 24,  # expire
        60 * 60 * 1,  # minimum
    )
)
ns_records = [NS(D.ns1), NS(D.ns2)]
records = {
    D: [A(IP), AAAA((0,) * 16), MX(D.mail), soa_record] + ns_records,
    D.ns1: [A(IP)],  # MX and NS records must never point to a CNAME alias (RFC 2181 section 10.3)
    D.ns2: [A(IP)],
    D.mail: [A(IP)],
    D.andrei: [CNAME(D)],
}


def dns_response(data):
    request = DNSRecord.parse(data)

    print(request)

    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

    qname = request.q.qname
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]

    #print(qn)
    #print(D)
    #print(qn == D)

    #if qn == 'dns.google.com.':
    #    reply.add_answer(RR(rname=DomainName(qn[:-1]), rtype=1, rclass=1, ttl=600, rdata=A('216.58.194.206')))
    #    return reply.pack()

    # TODO: If the domain is whitelisted then use DNSOverride
    '''
    if checkWitelist(qn[:-1]):
        a = DNSOverride(qn[:-1],qt)
        print(a.name)
        print((a.response.answer))
        print('---------')
        print(a.response.payload)
        print('----------')
        a = a.response.answer[0]
        print(a.to_rdataset()[0])
        print('**********')
        print(type(a.to_rdataset()))
        print(type(reply))
        #reply.add_answer(RR(a))
        #print(dict(a))
        reply.add_answer(RR(rname=DomainName(a.name), rtype=a.rdtype, rclass=a.rdclass, ttl=a.ttl, rdata=A(str(a.to_rdataset()[0]))))
        return reply.pack()
    '''

    answer = requests.get('http://35.233.249.53:5000/dns/%s/%s' % (qn[:-1], qt)).json()


    #ttl = answer.get('Answer')[0].get('TTL')
    #ip = answer.get('Answer')[0].get('data')
    #t = answer.get('Answer')[0].get('type')

    for a in answer.get('Answer'):
        t = a.get('type')
        d = a.get('data')

        if  QTYPE[t] == 'A':
            ttl = answer.get('Answer')[0].get('TTL')
            reply.add_answer(RR(rname=DomainName(qn[:-1]), rtype=t, rclass=1, ttl=ttl, rdata=A(d)))
        if QTYPE[t] == 'AAAA':
            #ttl = answer.get('Answer')[0].get('TTL')
            reply.add_answer(RR(rname=DomainName(qn[:-1]), rtype=t, rclass=1, ttl=300, rdata=AAAA(d)))
        if QTYPE[t] == 'CNAME':
            ttl = answer.get('Answer')[0].get('TTL')
            reply.add_answer(RR(rname=DomainName(qn[:-1]), rtype=t, rclass=1, ttl=ttl, rdata=CNAME(d)))
        if QTYPE[t] == 'SOA':
            ttl = answer.get('Answer')[0].get('TTL')
            reply.add_answer(RR(rname=DomainName(qn[:-1]), rtype=t, rclass=1, ttl=ttl, rdata=SOA(d)))
    #reply.add_answer(RR(rname=D, rtype=QTYPE.NS, rclass=1, ttl=TTL, rdata=ns_records[0]))
    #reply.add_answer(RR(rname=D, rtype=QTYPE.SOA, rclass=1, ttl=TTL, rdata=soa_record))

    '''
    if qn[:-1] == D or qn.endswith('.' + D):
        print('1')
        for name, rrs in records.items():
            print('THIS')
            if name == qn:
                for rdata in rrs:
                    print(rdata)
                    rqt = rdata.__class__.__name__
                    if qt in ['*', rqt]:
                        reply.add_answer(RR(rname=qname, rtype=QTYPE[rqt], rclass=1, ttl=TTL, rdata=rdata))

        for rdata in ns_records:
            reply.add_answer(RR(rname=D, rtype=QTYPE.NS, rclass=1, ttl=TTL, rdata=rdata))

        reply.add_answer(RR(rname=D, rtype=QTYPE.SOA, rclass=1, ttl=TTL, rdata=soa_record))

    '''
    print("---- Reply:\n", reply)

    return reply.pack()


class BaseRequestHandler(socketserver.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        print("\n\n%s request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0],
                                               self.client_address[1]))
        try:
            data = self.get_data()
            #print(len(data), data)  # repr(data).replace('\\x', '')[1:-1]
            self.send_data(dns_response(data))
        except Exception:
            traceback.print_exc(file=sys.stderr)


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = int(data[:2].encode('hex'), 16)
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = binascii.hexlify(hex(len(data))[2:].zfill(4))
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


if __name__ == '__main__':
    print("Starting nameserver...")

    servers = [
        socketserver.ThreadingUDPServer(('', PORT), UDPRequestHandler),
        socketserver.ThreadingTCPServer(('', PORT), TCPRequestHandler),
    ]
    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        print("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()