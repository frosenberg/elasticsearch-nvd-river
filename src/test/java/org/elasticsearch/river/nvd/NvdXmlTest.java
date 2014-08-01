package org.elasticsearch.river.nvd;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import gov.nist.scap.schema.feed.vulnerability._2.Nvd;
import gov.nist.scap.schema.vulnerability._0.VulnerabilityType;

import java.io.IOException;
import java.io.StringWriter;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.eclipse.persistence.jaxb.JAXBContextProperties;
import org.elasticsearch.common.jackson.core.JsonFactory;
import org.elasticsearch.common.jackson.core.JsonParser;
import org.elasticsearch.common.jackson.core.JsonToken;
import org.junit.Test;

public class NvdXmlTest {

	@Test
	public void testParsing() throws JAXBException, IOException {
		
    URL resource = getClass().getResource("/nvdcve-2.0-2003.xml");
    System.out.println("Parsing " + resource);
		
		JAXBContext jaxbContext = JAXBContext.newInstance(Nvd.class);
		
		Unmarshaller um = jaxbContext.createUnmarshaller();
		Nvd nvd = (Nvd)um.unmarshal(resource.openStream());
		
		System.out.println("Nvd: " + nvd.getEntry().size());
		
		assertEquals(1515, nvd.getEntry().size());
	}
	
//	@Test
//	public void testHeadTime() throws IOException, ParseException {
//		URL resource = new URL("http://nvd.nist.gov/download/nvdcve-modified.xml");		
//		URLConnection conn = resource.openConnection();		
//		String lastModified = conn.getHeaderField("Last-Modified");
//		System.out.println("lastModified: " + lastModified);		
//		assertNotNull(lastModified);
//		
//		SimpleDateFormat format = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz");
//		Date d = format.parse(lastModified);
//		System.out.println("Dateformat: " + d);
//		assertNotNull(d);
//		
//		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
//		// this is the ES target format 2014-07-26T11:55:03.777-04:00
//		StringBuilder sb = new StringBuilder(sdf.format(d));
//		int len = sb.length();
//		sb.replace(len-5, len-4, "-");
//		sb.insert(len-2, ':');
//		System.out.println(sb.toString());
//		
//	}
	
	@Test
	public void testXml2Json() throws JAXBException, IOException {
		// read XML into a JAXB object structure
		URL resource = getClass().getResource("/nvdcve-2.0-2003.xml");
	  System.out.println("Parsing " + resource);	
		JAXBContext jaxbContext = JAXBContext.newInstance(Nvd.class);
		Unmarshaller um = jaxbContext.createUnmarshaller();
		Nvd nvd = (Nvd)um.unmarshal(resource.openStream());
    
    // JAXB to JSON properties
    Map<String, Object> properties = new HashMap<String, Object>(2);
    properties.put(JAXBContextProperties.MEDIA_TYPE, "application/json");
    properties.put(JAXBContextProperties.JSON_INCLUDE_ROOT, false);
		
    // convert a single CVE entry to JSON
    JAXBContext jc = JAXBContext.newInstance(new Class[] { VulnerabilityType.class }, properties);
    Marshaller marshaller = jc.createMarshaller();
    marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
    StringWriter swriter = new StringWriter();
    for (VulnerabilityType entry : nvd.getEntry()) {
    	marshaller.marshal(entry, swriter);
      assertTrue(swriter.toString().startsWith("{"));
    }
    
    jc = JAXBContext.newInstance(new Class[] { Nvd.class }, properties);
    marshaller = jc.createMarshaller();
    marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
    swriter = new StringWriter();
    marshaller.marshal(nvd, swriter);
    
    JsonParser p = new JsonFactory().createParser(swriter.toString());
    JsonToken token = null;
    int level = 0, cveEntries = 0;

    while ((token = p.nextValue()) != null) {
    	if (token.isStructStart()) {
    		level++;
    	} else if (token.isStructEnd()) {
    		level--;
    	}   
    	if (level == 2) cveEntries++; // we want to count all CVEs in the array that is at level 2
    }
    p.close();
    System.out.printf("cveEntries = %s", cveEntries);
    assertEquals(1515, cveEntries-1);    
  }	

}
