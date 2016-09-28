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
  
  def run(self, filename, is_ddos, parser):
    """ Run normalization
    :param filename:str -> File to parse.
    :param is_ddos:bool [0|1] -> Reather the dataset is from a DDoS attack or Legit Traffic.
    :param parser:string [iptables|tcpdump] -> Currently support parse for `tcpdump` output and `iptables ... -j LOG`
    """
    print 'parsing %s log...' % parser
    with open(filename, "r") as f:
      raw = f.read().splitlines()
    
    bar = progressbar.ProgressBar(maxval=len(raw)).start()
    for i in range(0, len(raw)):
      try:
        if parser == 'iptables':
          src_ip_tcp, src_port, dst_port = re.findall(r'SRC=(.+?) .+?SPT=(.+?) DPT=(.+?) ', raw[i])[0]
        elif parser == 'tcpdump':
          src_ip_tcp, src_port, dst_port = re.findall(r'IP (.+?\..+?\..+?\..+?)\.(.+?) > .+?\..+?\..+?\..+?\.(.+?):', raw[i])[0]
        else:
          print 'heuuu'
          raise Exception('Parser not supported: %s ' % parser)

        entry = self.get_ip_geo_info(src_ip_tcp)
        entry['src_port'] = int(src_port)
        entry['dst_port'] = int(dst_port)
        entry['is_ddos'] = is_ddos
        self.data.append(entry)
      except Exception, e:
        print e
        pass# skipped. Could not parse.x
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
      json.dump(self.data[0], f)

  def print_data(self):
    print json.dumps(self.data, indent=2)  
if __name__ == "__main__":
  import os, re
  path = './cainelli/mackenzie/tensorflow-ddos/dataset/load/'
  loads = os.listdir(path)
  p = Parser()
  for file in loads:
    parser, is_ddos = re.findall(r'(iptables|tcpdump).+?cnli', file), re.findall(r'(ddos|legit).+?cnli', file)
    if parser and is_ddos:
      is_ddos = 1 if is_ddos == 'ddos' else 0 
      p.run(
        filename=path+file,
        parser=parser[0],
        is_ddos=is_ddos
      )

  p.print_data()