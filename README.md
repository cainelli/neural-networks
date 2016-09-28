# tensorflow-ddos
This project contains the following components:

# Telize
Telize is a API to retrieve GeoIP information utilized by the normaliz process.

# Normaliz
When you run *Normaliz* for the first time it will batch a process to normalize the dataset. 
When this process ends it opens a API to normalize the input data required for each further test.

# Learn
The learn process requires that the data was normalized so it waits for *Normaliz* finish its batch processing
to begin the his own process of trainig.