
import pandas
import numpy as np
from sklearn import metrics, cross_validation

import tensorflow as tf
from tensorflow.contrib import layers
#from tensorflow.contrib import learn
#
import tensorflow.contrib.learn.python.learn as learn



data = pandas.read_json('/Users/cainelli/Documents/workspace/cainelli/mackenzie/neural_networks/code/data.json')
X = data[[
  "ip", "src_port", "dst_port", "city",
  "organization", "continent_code","country",
  "region", "area_code",
  "longitude", "country_code3", 
  "region_code", "dma_code", "country_code", 
  "offset", "latitude"]]
y = data["is_ddos"]

X_train, X_test, y_train, y_test = cross_validation.train_test_split(X, y, test_size=0.2, random_state=42)


#def categorical_model(features, target):
#    target = tf.one_hot(target, 2, 1.0, 0.0)
#    prediction, loss = learn.models.logistic_regression(features, target)
#    train_op = layers.optimize_loss(loss,
#        tf.contrib.framework.get_global_step(), optimizer='SGD', learning_rate=0.05)
#    return tf.argmax(prediction, dimension=1), loss, train_op

#classifier = skflow.Estimator(model_fn=categorical_model)
classifier = learn.LinearRegressor()
classifier.fit(X_train, y_train, steps=1000)

#score = metrics.mean_squared_error(classifier.predict(X), y)
#print ("MSE: %f" % score)

#
print("Accuracy: {0}".format(metrics.accuracy_score(classifier.predict(X_test), y_test)))
