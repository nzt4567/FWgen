#!/usr/bin/env python3

'''
  very simple netfilter rules generator - edit to suit your needs
  settings do of course NOT match my true network settings
  nzt4567@gmx.com, 2013
'''

m_command = "/usr/sbin/iptables"
m_tables  = ('filter', 'nat', 'mangle', 'raw')
m_clients = { 
            "host1": {"IP": "192.168.1.1", "MAC": "FF:00:00:00:00:00"},
            "host2": {"IP": "192.168.1.2", "MAC": "FF:FF:00:00:00:00"},
            "host3": {"IP": "192.168.1.3", "MAC": "FF:FF:FF:00:00:00"}
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
                          "type": "private"
                        }
              }

def gen_filter():

  def gen_io():
    pass

  def gen_forward():
    pass

  chains = (gen_io, gen_forward)

def gen_nat():

  def gen_pre():
    pass

  def gen_in():
    pass

  def gen_out():
    pass

  def gen_post():
    pass

  chains = (gen_pre, gen_in, gen_out, gen_post)

def gen_mangle():

  def gen_pre():
    pass

  def gen_in():
    pass

  def gen_out():
    pass

  def gen_forward():
    pass

  def gen_post():
    pass

  chains = (gen_pre, gen_in, gen_out, gen_forward, gen_post)

def gen_raw():

  def gen_pre():
    pass

  def gen_out():
    pass

  chains = (gen_pre, gen_out)

def gen_tables():
  tables = (gen_filter, gen_nat, gen_mangle, gen_raw)

def clean_tables(tables=m_tables):
  pass

def set_policy(policy="DROP"):
  pass # an all tables other than filter set ACCEPT, on filter set policy

def set_misc():
  pass

def gen_defaults():
  defaults = (clean_tables, set_policy, set_misc)

def gen_fw():
  return ''.join(gen_defaults() + gen_tables())