#!/usr/bin/python
print 'import modules...'
import re, os, requests, json
import pandas as pd 
import progressbar
import tensorflow.contrib.learn as skflow
import numpy as np
import matplotlib.pyplot as plt
from sklearn import preprocessing
from sklearn import metrics, cross_validation
from mpl_toolkits.basemap import Basemap
print 'done.'

class Parser(object):
  def __init__(self, telize_url='http://localhost/geoip/'):
    self.telize_url = telize_url
    self.features = ["ip", "src_port", "dst_port", "city", "organization", "continent_code",
              "country", "region", "area_code", "longitude", "country_code3", "region_code", "dma_code", "country_code", "offset",
              "latitude"]
    self.X = [] # inputs
    self.Y = [] # desired

  def run(self, filename, is_ddos, parser, workdir):
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
          src_ip_tcp, src_port, dst_port, ulen = re.findall(r'SRC=(.+?) .+?SPT=(.+?) DPT=(.+?) LEN=(.+?)$', raw[i])[0]
        elif parser == 'tcpdump':
          src_ip_tcp, src_port, dst_port = re.findall(r'IP (.+?\..+?\..+?\..+?)\.(.+?) > .+?\..+?\..+?\..+?\.(.+?):', raw[i])[0]
        else:
          raise Exception('Parser not supported: %s ' % parser)

        entry = self.get_ip_geo_info(src_ip_tcp)
        entry['src_port'] = int(src_port)
        entry['dst_port'] = int(dst_port)
        entry['ulen'] = int(ulen)
        self.Y.append(is_ddos)
        self.X.append(entry)
      except Exception, e:
        print filename
        #print e
        pass# skipped. Could not parse.x
      bar.update(i)
    
    bar.finish()
    self.save_data(workdir)
    
    # preprocessing
    self.pd_X = pd.read_json(json.dumps(self.X))
    self.X_normalized = preprocessing.normalize(self.pd_X, norm='l2')
  
  def load(self):
    self.load_data(workdir)
  
  def get_ip_geo_info(self, ip):
    r = requests.get(self.telize_url + ip)
    d = {}
    for f in self.features:
      d[f] = r.json().get(f) or 0
      try:
        d[f] = float(d[f]) # convert num string to int
      except:
        d[f] = abs(hash(d[f])) % (10 ** 8) # convert string to numerical hash.
    return d

  def save_data(self, fold):
    with open(fold + '/X', 'w') as f:
      json.dump(self.X, f)
    with open(fold + '/Y', 'w') as f:
      json.dump(self.Y, f)

  def load_data(self, fold): 
    print 'loading %s' % (fold + 'X')
    with open(fold + '/X', 'r') as f:
      self.X = json.load(f)
    print 'loading %s' % (fold + 'Y')  
    with open(fold + '/Y', 'r') as f:
      self.Y = json.load(f)
    
    # preprocessing
    print 'creating pd_X'
    self.pd_X = pd.read_json(json.dumps(self.X))
    print 'creating X_normalized'
    # self.X_normalized = preprocessing.normalize(self.pd_X, norm='l2')
    self.X_normalized = preprocessing.normalize(self.pd_X[['ulen', 'ip', 'src_port', 'dst_port']], norm='l2')
  def print_json(self):
    print json.dumps(self.X, indent=2)

if __name__ == "__main__":
  
  # workdir = '/Users/cainelli/Documents/workspace/cainelli/mackenzie/tensorflow-ddos/dataset/load/utilized/size_equivalence/1/'
  workdir = "/Users/cainelli/Documents/workspace/cainelli/mackenzie/tensorflow-ddos/dataset/load/utilized/time_equivalence/1/"
  skip_parse = True
  
  loads = os.listdir(workdir)
  p = Parser()

  # Load Data
  if skip_parse:
    p.load_data(workdir)
    print 'done'
  else:
    for file in loads:
      parser, is_ddos = re.findall(r'(iptables|tcpdump)', file), re.findall(r'(ddos|legit)', file)
      if parser and is_ddos:
        is_ddos = 1 if is_ddos[0] == 'ddos' else 0
        print 'running parser is_ddos:[%s]' % is_ddos
        p.run(
          filename=workdir+file,
          parser=parser[0],
          is_ddos=is_ddos,
          workdir=workdir
        )

  # Learn Network
  print 'split test and train'
  X_train, X_test, y_train, y_test = cross_validation.train_test_split(p.X_normalized, p.Y, test_size=0.2, random_state=42)      
  def categorical_model(X, y):
    return skflow.models.logistic_regression(X, y)
    
  # classifier = skflow.TensorFlowEstimator(model_fn=categorical_model,
  #   n_classes=4, learning_rate=0.07)
  
  #hiddens = [[2], [4, 4], [8, 8, 8], [16, 16, 16, 16], [32, 32, 32, 32, 32], [64, 64, 64, 64, 64, 64], [128, 128, 128, 128, 128, 128, 128]]
  hiddens = [[128, 128, 128, 128, 128, 128, 128]]
  # hiddens = [[2]]
  from timeit import default_timer as timer
  for hidecfg in hiddens:
    start = timer()
    classifier = skflow.DNNClassifier(hidden_units=hidecfg, n_classes=4)
    classifier.fit(X_train, y_train, steps=300)
    end = timer()
    accuracy = metrics.accuracy_score(classifier.predict(X_test), y_test)

    print '%s; %s; %s; %s' % (16, hidecfg, accuracy, ( end - start))

  # def outliers(df, threshold, columns):
  #   for col in columns: 
  #     mask = df[col] > float(threshold)*df[col].std()+df[col].mean()
  #     df.loc[mask == True,col] = np.nan
  #     mean_property = df.loc[:,col].mean()
  #     df.loc[mask == True,col] = mean_property
  #   return df
  
  # print 'copping pd_X to X_cleanned'
  # X_cleaned = p.pd_X.copy()
  # print 'removing outliers'
  # X_cleaned = outliers(X_cleaned, 5, ['latitude', 'longitude'])
  
  # # Create a figure of size (i.e. pretty big)
  # print 'creating:'
  # print '..fig'
  # fig = plt.figure(figsize=(20,10))
  
  # # Create a map, using the Gall Peters projection
  # print '..basemap'
  # m = Basemap(projection='gall', 
  #               # with low resolution,
  #               resolution = 'l', 
  #               # And threshold 100000
  #               area_thresh = 100000.0,
  #               # Centered at 0,0 (i.e null island)
  #               lat_0=0, lon_0=0)
  
  # # Draw the coastlines on the map
  # print '..coast lines'
  # m.drawcoastlines()
  
  # # Draw country borders on the map
  # print '..country borders'
  # m.drawcountries()
  
  # # Fill the land with grey
  # print '..filling land'
  # m.fillcontinents(color = '#888888')
  
  # # Draw the map boundaries
  # print '..boundaries'
  # m.drawmapboundary(fill_color='#f4f4f4')
  
  # # Define our longitude and latitude points
  # print '..copying points'
  # x,y = m(p.pd_X['longitude'].values, p.pd_X['latitude'].values)
  
  # # Plot them using round markers of size 6
  # print '...ploting points'
  # m.plot(x, y, 'ro', markersize=6)
    
  # lonlat = -23.5477; lonlon = -46.6358
  # idx = 0
  # print '..source x destination lines'
  # for index, row in X_cleaned.iterrows():
  #   if p.Y[idx] == 1:
  #     #print 'skip'
  #     m.drawgreatcircle(row['longitude'],row['latitude'],lonlon,lonlat,linewidth=1,color='r')
  #   else:
  #     pass 
  #     #m.drawgreatcircle(row['longitude'],row['latitude'],lonlon,lonlat,linewidth=1,color='b')
  #   idx += 1
  # print '...cost lines (again?)'  
  # m.drawcoastlines()
  # print '...saving figure %s' % workdir + 'ddos_image.png'
  # fig.savefig(workdir + 'ddos_image.png')
  # print 'Done.'
  #plt.show()