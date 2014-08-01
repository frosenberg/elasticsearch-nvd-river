# NVD River for ElasticSearch
=============================

Welcome to the NVD River Plugin for [Elasticsearch](http://www.elasticsearch.org/). The purpose of
this plugin is to read the CVE vulnerability XML feeds of the National Vulnerability Database and push 
it into ElasticSearch. Another purpose was to learn ElasticSearch and get some hands on experience.


## Versions
-----------

* For 1.3.x elasticsearch versions, look at [master branch](https://github.com/frosenberg/elasticsearch-nvd-river/tree/master).

The plugin code is considered highly experimental and was only tested with Java 7.

## Installing 

  1. `~/code$ git clone https://github.com/frosenberg/elasticsearch-nvd-river`
  2. `~/code$ cd elasticsearch-nvd-river`
  3. `~/code/elasticsearch-nvd-river$ mvn clean package` (will take a while b/c of some long running tests)
  4. Copy the package from `~/code/elasticsearch-nvd-river/target/release/nvdriver-1.0.0-SNAPSHOT.zip` to your ElasticSearch instance
  5. `bin/plugin --url file:///path/to/nvdriver-1.0.0-SNAPSHOT.zip --install nvdriver`


## Usage 

You just need to execute a few simple cURL command to feed the data from the NIST NVD database.

### Create an index

    curl -XPUT 'http://localhost:9200/nvd/' -d '{}'


### Create a mapping

Mappings are not needed and currently not supported. I did not see the need in my use case. ElasticSearch has pretty good 
dynamic mapping generation that was sufficient. If you feel the need to customize the mapping 
please open an issue or contribute.

### Create the river

This will create a river and will push in the following XML feed. You can of course add more 
if needed, or remove some. Keep in mind this may take some time until all of the are processed.

  	curl -XPUT 'localhost:9200/_river/nvd/_meta' -d '{
  	  "type": "nvd",
  	  "nvd": {
  	    "streams" : [
  	      {
  	        "name": "cve-modified",
  	        "url": "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-modified.xml"
  	      },
  	      {
  	        "name": "cve-2014",
  	        "url": "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2014.xml"
  	      },
  	      {
  	        "name": "cve-2013",
  	        "url": "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2013.xml"
  	      },
  	      {
  	        "name": "cve-2012",
  	        "url": "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2012.xml"
  	      },
  	      {
  	        "name": "cve-2011",
  	        "url": "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2011.xml"
  	      },
  	      {
  	        "name": "cve-2010",
  	        "url": "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2010.xml"
  	      }
  	    ]
  	  }
  	}'


### Test the river plugin

    curl -XGET 'http://localhost:9200/nvd/_search?q=oracle'

## Developer Notes

The code contains a lot of generated classes that were generated from the CVE XML schema 2.0
located at [http://nvd.nist.gov/schema/nvd-cve-feed_2.0.xsd]

### Compiling the NVD XML schema files:

The following command will compile the schema into Java JAXB version 2.1 data bindings.  

    ~/code/elasticsearch-nvd-river$ xjc -d src/main/java/ -target 2.1 http://nvd.nist.gov/schema/nvd-cve-feed_2.0.xsd

We do not use a specific namespace to Java package customization because this will only complicate matters.
