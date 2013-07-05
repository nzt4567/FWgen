#!/usr/bin/env python3

'''
  very simple netfilter rules generator - edit to suit your needs
  settings do of course NOT match my true network settings
  nzt4567@gmx.com, 2013
'''

# IMPORTS


# CREDITS
__author__  = "nzt4567"
__email__   = "nzt4567@gmx.com"
__status__  = "devel"
__version__ = "0.1"
__license__ = "GNU GPL v3"
__year__    = "2013"


################################# CONSTANTS #############################
#########################################################################
m_command = "/usr/sbin/iptables"
m_tables  = ('filter', 'nat', 'mangle', 'raw')
m_clients = "1024:65535"
m_anywhere = "0.0.0.0/0"
m_broadcast = "255.255.255.255"
m_stateless = "INVALID,NEW,ESTABLISHED,RELATED,UNTRACKED"
m_hosts = { 
            "host1":  {
                        "eth0": { 
                                  "IP": "192.168.1.1", 
                                  "MAC": "FF:00:00:00:00:00"
                                },
                        "wln0": {
                                  "IP": "192.168.4.1",
                                  "MAC": "00:FF:00:FF:00:FF"
                                }
                      },
            "host2": {
                        "eth0": { 
                                  "IP": "192.168.1.2", 
                                  "MAC": "FF:FF:00:00:00:00"
                                },
                        "wln0": {
                                  "IP": "192.168.4.2",
                                  "MAC": "00:FF:FF:FF:00:FF"
                                }
                      },
            "host3": {
                        "eth0": { 
                                  "IP": "192.168.1.3", 
                                  "MAC": "FF:00:00:FF:00:00"
                                },
                        "wln0": {
                                  "IP": "192.168.4.3",
                                  "MAC": "00:FF:00:FF:FF:FF"
                                }
                      }
          }
m_interfaces =  {
                  "eth0": 
                          {
                            "IP": "192.168.2.1", 
                            "MAC:": "00:00:00:00:00:FF",
                            "net": "192.168.2.0/27",
                            "mtu": "42",
                            "type": "wan"
                          },
                  "wln0":
                          {
                            "IP": "192.168.3.1", 
                            "MAC:": "00:00:00:00:FF:FF",
                            "net": "192.168.3.0/27",
                            "mtu": "43",
                            "type": "wan"
                          }
                }
############################### FW GENERATING ###########################
#########################################################################

################################ FILTER TABLE ###########################
def gen_filter(trg="ACCEPT"):
  ret = list()
  name = "filter"

  def gen_in(trg="ACCEPT"):
    ret = list()
    name = "INPUT"

    def gen_dhcp_s(trg="ACCEPT"):
      ret = list()
      interfaces = tuple([x for x in m_interfaces \
        if m_interfaces[x]["type"] == "private" or \
        m_interfaces[x]["type"] == "public"])
      prt = "UDP"
      src = {interfaces[i]:m_anywhere for i in range(0,len(interfaces))}
      s_p = "68"
      dst = {interfaces[i]:m_broadcast for i in range(0,len(interfaces))}
      d_p = "67"
      sta = m_stateless

      for i in interfaces:
        ret.append(m_command + " -A " + name + " -p " + prt + " -i " + \
          i + " --src " + src[i] + " --dst " + dst[i] + " --sport " + \
          s_p + " --dport " + d_p + " -m state --state " + sta + \
          " -j " + trg + "\n")

      return ret
        
    def gen_dns_s(trg="ACCEPT"):
      ret = list()
      interfaces = tuple([x for x in m_interfaces \
        if m_interfaces[x]["type"] == "private" or \
        m_interfaces[x]["type"] == "public"])
      prt = ("TCP", "UDP")
      src = {interfaces[i]:m_interfaces[interfaces[i]]["net"] \
        for i in range(0, len(interfaces))}
      s_p = m_clients
      dst = {interfaces[i]:m_interfaces[interfaces[i]]["IP"] \
        for i in range(0, len(interfaces))}
      d_p = "53"
      sta = "NEW,ESTABLISHED"

      for i in interfaces:
        for p in prt:
          ret.append(m_command + " -A " + name + " -p " + p + " -i " + \
          i + " --src " + src[i] + " --dst " + dst[i] + " --sport " + \
          s_p + " --dport " + d_p + " -m state --state " + sta + \
          " -j " + trg + "\n")

      return ret

    def gen_ssh_s(trg="ACCEPT"):
      ret = list()
      interfaces = tuple([x for x in m_interfaces \
        if m_interfaces[x]["type"] == "private"])
      prt = "TCP"
      src = {interfaces[i]:tuple([m_hosts[n][interfaces[i]]["IP"] \
        for n in m_hosts if n == "host1" or n == "host2"]) \
        for i in range(0, len(interfaces))}
      s_p = m_clients
      dst = {interfaces[i]:m_interfaces[interfaces[i]]["IP"] \
        for i in range(0, len(interfaces))}
      d_p = "22"
      sta = "NEW,ESTABLISHED"

      for i in interfaces:
        for s in src[i]:
          ret.append(m_command + " -A " + name + " -p " + prt + " -i " + \
          i + " --src " + s + " --dst " + dst[i] + " --sport " + \
          s_p + " --dport " + d_p + " -m state --state " + sta + \
          " -j " + trg + "\n")

      return ret

    def gen_http_c(trg="ACCEPT"):
      ret = list()

      return ret

    def gen_dns_c(trg="ACCEPT"):
      ret = list()
      dns_servers = ("8.8.8.8", "8.8.4.4")
      interfaces = tuple([x for x in m_interfaces \
        if m_interfaces[x]["type"] == "wan"])
      prt = ("TCP", "UDP")
      src = {interfaces[i]:dns_servers for i in range(0,len(interfaces))}
      s_p = "53"
      dst = {interfaces[i]:m_interfaces[interfaces[i]]["IP"] \
        for i in range(0, len(interfaces))}
      d_p = m_clients
      sta = "ESTABLISHED"

      for i in interfaces:
        for s in src[i]:
          for p in prt:
            ret.append(m_command + " -A " + name + " -p " + p + " -i " + \
            i + " --src " + s + " --dst " + dst[i] + " --sport " + \
            s_p + " --dport " + d_p + " -m state --state " + sta + \
            " -j " + trg + "\n")

      return ret

    def gen_ntp_c(trg="ACCEPT"):
      ret = list()

      return ret

    servers = (gen_dhcp_s, gen_dns_s, gen_ssh_s)
    clients = (gen_http_c, gen_dns_c, gen_ntp_c)
    # do not forget to generate one rule for loopback interface - ACCEPT ALL

    for s in servers:
      ret += s(trg)

    for c in clients:
      ret += c(trg)

    return ret

  def gen_out(trg="ACCEPT"):
    ret = list()

    return ret

  def gen_forward(trg="ACCEPT"):
    ret = list()

    return ret

  chains = (gen_in, gen_out, gen_forward)

  for ch in chains:
    ret += ch()

  return ret


################################### NAT TABLE ###########################
def gen_nat():
  ret = list()
  name = "nat"

  def gen_pre(trg="DNAT"):
    ret = list()
    name = "PREROUTING"

    return ret

  def gen_in():
    ret = list()
    name = "INPUT"

    return ret

  def gen_out():
    ret = list()
    name = "OUTPUT"

    return ret

  def gen_post(trg="MASQUERADE"):
    ret = list()
    name = "POSTROUTING"

    return ret

  chains = (gen_pre, gen_in, gen_out, gen_post)

  for ch in chains:
    ret += ch()

  return ret

################################# MANGLE TABLE ##########################
def gen_mangle():
  ret = list()
  name = "mangle"

  def gen_pre():
    ret = list()
    name = "PREROUTING"

    return ret

  def gen_in():
    ret = list()
    name = "INPUT"

    return ret

  def gen_out():
    ret = list()
    name = "OUTPUT"

    return ret

  def gen_forward(trg="TCPMSS --clamp-mss-to-pmtu"):
    ret = list()
    name = "FORWARD"

    return ret

  def gen_post():
    ret = list()
    name = "POSTROUTING"

    return ret

  chains = (gen_pre, gen_in, gen_out, gen_forward, gen_post)

  for ch in chains:
    ret += ch()

  return ret

################################### RAW TABLE ###########################
def gen_raw():
  ret = list()
  name = "raw"

  def gen_pre():
    ret = list()
    name = "PREROUTING"

    return ret

  def gen_out():
    ret = list()
    name = "OUTPUT"

    return ret

  chains = (gen_pre, gen_out)

  for ch in chains:
    ret += ch()

  return ret

def gen_tables():
  ret = list()

  tables = (gen_nat, gen_mangle, gen_raw, gen_filter)
  for t in tables:
    ret += t()

  return ret

def clean_tables(tables=m_tables):
  ret = list()

  return ret

def set_policy(policy="DROP"):
  ret = list()

  return ret # an all tables other than filter set ACCEPT, on filter set policy

def set_misc():
  ret = list()

  return ret

def gen_defaults():
  ret = list()

  defaults = (clean_tables, set_policy, set_misc)
  for d in defaults:
    ret += d()

  return ret

def gen_fw():
  return ''.join(gen_defaults() + gen_tables())

print(gen_fw())