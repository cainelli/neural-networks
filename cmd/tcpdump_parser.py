#!/usr/bin/python
import re, requests, json
import pandas as pd 
import progressbar


class Parser(object):
  def __init__(self, telize_url='http://localhost/geoip/'):
    self.telize_url = telize_url
    self.features = ["ip", "src_port", "dst_port", "city", "organization", "continent_code",
              "country", "region", "area_code", "longitude", "country_code3", "region_code", "dma_code", "country_code", "offset",
              "latitude"]
    self.data = []
  
  def iptables(self, filename):
    print 'parsing iptables logs...'
    with open(filename, "r") as f:
      raw = f.read().splitlines()
    
    bar = progressbar.ProgressBar(maxval=len(raw)).start()
    for i in range(0, len(raw)):
      try:
        src_ip_tcp, src_port, dst_port = re.findall(r'SRC=(.+?) .+?SPT=(.+?) DPT=(.+?) ', raw[i])[0]
        
        entry = self.get_ip_geo_info(src_ip_tcp)
        entry['src_port'] = int(src_port)
        entry['dst_port'] = int(dst_port)
        entry['is_ddos'] = 1
        self.data.append(entry)
      except:
        pass# skipped. Could not parse.x
      bar.update(i)
    
    bar.finish()
        
  def tcpdump(self, filename):
    with open(filename, "r") as f:
      raw = f.read().splitlines()
    print 'parsing tcpdump logs...'
    bar = progressbar.ProgressBar(maxval=len(raw)).start()
    for i in range(0, len(raw)):
      try:
        src_ip_tcp, src_port, dst_port = re.findall(r'IP (.+?\..+?\..+?\..+?)\.(.+?) > .+?\..+?\..+?\..+?\.(.+?):', raw[i])[0]
        
        entry = self.get_ip_geo_info(src_ip_tcp)
        entry['src_port'] = int(src_port)
        entry['dst_port'] = int(dst_port)
        entry['is_ddos'] = 0
        self.data.append(entry)
      except:
        pass
        # skipped. Could not parse.x
      bar.update(i)
    
    bar.finish()
  
  def get_ip_geo_info(self, ip):
    r = requests.get(self.telize_url + ip)
    d = {}
    for f in self.features:
      d[f] = r.json().get(f) or 0
      try:
        d[f] = int(d[f]) # convert num string to int
      except:
        d[f] = abs(hash(d[f])) % (10 ** 8) # convert string to numerical hash.
    return d

  def save_data(self, filename):
    with open(filename, 'w') as f:
      json.dump(self.data, f)

  def print_data(self):
    print json.dumps(self.data, indent=2)  
if __name__ == "__main__":
  p = Parser()

  p.tcpdump(filename="legit.raw")
  #p.iptables(filename="evidence.txt")
  #p.save_data(filename="data.json")
  
