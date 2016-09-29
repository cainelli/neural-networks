#!/usr/bin/python
import re, requests, json
import pandas as pd 
import progressbar
from sklearn import preprocessing
import tensorflow.contrib.learn as skflow
from sklearn import metrics, cross_validation

class Parser(object):
  def __init__(self, telize_url='http://localhost/geoip/'):
    self.telize_url = telize_url
    self.features = ["ip", "src_port", "dst_port", "city", "organization", "continent_code",
              "country", "region", "area_code", "longitude", "country_code3", "region_code", "dma_code", "country_code", "offset",
              "latitude"]
    self.X = [] # inputs
    self.Y = [] # desired

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
          raise Exception('Parser not supported: %s ' % parser)

        entry = self.get_ip_geo_info(src_ip_tcp)
        entry['src_port'] = int(src_port)
        entry['dst_port'] = int(dst_port)
        self.Y.append(is_ddos)
        self.X.append(entry)
      except Exception, e:
        print e
        pass# skipped. Could not parse.x
      bar.update(i)
    
    bar.finish()

    # preprocessing
    self.pd_X = pd.read_json(json.dumps(self.X))
    self.X_normalized = preprocessing.normalize(self.pd_X, norm='l2')
  
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
    pass
#    with open(filename+'_inputs, 'w') as f:
#      json.dump(self.X_normalized, f)
#    with open(filename+'_y, 'w') as f:
#      json.dump(self.Y, f)

  def print_json(self):
    print json.dumps(self.X, indent=2)

if __name__ == "__main__":
  import os, re
  path = '/Users/cainelli/Documents/workspace/cainelli/mackenzie/tensorflow-ddos/dataset/load/'
  loads = os.listdir(path)
  p = Parser()
  # Load Data 
  for file in loads:
    parser, is_ddos = re.findall(r'(iptables|tcpdump).+?cnli', file), re.findall(r'(ddos|legit).+?cnli', file)
    if parser and is_ddos:
      is_ddos = 1 if is_ddos[0] == 'ddos' else 0
      p.run(
        filename=path+file,
        parser=parser[0],
        is_ddos=is_ddos
      )

  # Learn Network      
  def categorical_model(X, y):
    return skflow.models.logistic_regression(X, y)
    
  X_train, X_test, y_train, y_test = cross_validation.train_test_split(p.X_normalized, p.Y, test_size=0.2, random_state=42)
  classifier = skflow.TensorFlowEstimator(model_fn=categorical_model,
    n_classes=16, learning_rate=0.07)
  classifier.fit(X_train, y_train)
  
  print("Accuracy: {0}".format(metrics.accuracy_score(classifier.predict(X_test), y_test)))

