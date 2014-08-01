package org.elasticsearch.river.nvd;

import static org.elasticsearch.client.Requests.indexRequest;
import gov.nist.scap.schema.feed.vulnerability._2.Nvd;
import gov.nist.scap.schema.vulnerability._0.VulnerabilityType;

import java.io.IOException;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.eclipse.persistence.jaxb.JAXBContextProperties;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.action.bulk.*;
import org.elasticsearch.action.bulk.BulkProcessor.Listener;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.joda.time.format.ISODateTimeFormat;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.util.concurrent.EsExecutors;
import org.elasticsearch.common.xcontent.support.XContentMapValues;
import org.elasticsearch.indices.IndexAlreadyExistsException;
import org.elasticsearch.river.AbstractRiverComponent;
import org.elasticsearch.river.River;
import org.elasticsearch.river.RiverName;
import org.elasticsearch.river.RiverSettings;

/**
 * Implement a Elasticsearch river plugin for fetching NIST's National Vulnerability
 * Database provided as a set of XML files and pumps individual CVE entries in the store.
 * 
 * @author Florian Rosenberg
 */
public class NvdRiver extends AbstractRiverComponent implements River {

	private static final String					NVD_TYPE		= "nvd";

	private final Client								client;

	private final String								indexName;

	private final int										bulkSize;
	private final TimeValue							bulkFlushInterval;
	private final int										maxConcurrentBulk;
	private volatile BulkProcessor			bulkProcessor;

	private final ArrayList<NvdEntry>		nvdEntries	= new ArrayList<NvdEntry>();
	private volatile ArrayList<Thread>	threads;
	private volatile boolean						closed;

	@SuppressWarnings("unchecked")
	@Inject
	public NvdRiver(RiverName riverName, RiverSettings settings, Client client) {
		super(riverName, settings);
		this.client = client;
		logger.info("Creating 'nvd-river' ...");

		if (settings.settings().containsKey(NVD_TYPE)) {
			Map<String, Object> nvdSettings = (Map<String, Object>) settings
					.settings().get(NVD_TYPE);

			// Get a list of NVD streams to fetch
			boolean array = XContentMapValues.isArray(nvdSettings.get("streams"));
			if (array) {
				ArrayList<Map<String, Object>> streams = (ArrayList<Map<String, Object>>) nvdSettings
						.get("streams");

				for (Map<String, Object> e : streams) {
					logger.debug(streams.toString());
					String name = XContentMapValues.nodeStringValue(e.get("name"), null);
					String url = XContentMapValues.nodeStringValue(e.get("url"), null);
					TimeValue updateRate = TimeValue.parseTimeValue(
							XContentMapValues.nodeStringValue(e.get("update_rate"), null), 
							TimeValue.timeValueMinutes(720));
					nvdEntries.add(new NvdEntry(name, url, updateRate));
				}
			}
		} else {
			String url = "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-modified.xml";
			logger
					.warn(
							"You didn't define the NVD XML feed url. Switching to defaults : [{}]",
							url);
			nvdEntries.add(new NvdEntry("nvdcve-2.0-modified", url, TimeValue
					.timeValueMinutes(720)));
		}

		if (settings.settings().containsKey("index")) {
			Map<String, Object> indexSettings = (Map<String, Object>) settings
					.settings().get("index");
			indexName = XContentMapValues.nodeStringValue(indexSettings.get("index"),
					riverName.name());
			bulkSize = XContentMapValues.nodeIntegerValue(
					indexSettings.get("bulk_size"), 25);
			bulkFlushInterval = TimeValue.parseTimeValue(XContentMapValues
					.nodeStringValue(indexSettings.get("flush_interval"), null),
					TimeValue.timeValueSeconds(5));
			maxConcurrentBulk = XContentMapValues.nodeIntegerValue(
					indexSettings.get("max_concurrent_bulk"), 1);
		} else {
			indexName = riverName.name();
			bulkSize = 100;
			maxConcurrentBulk = 1;
			bulkFlushInterval = TimeValue.timeValueSeconds(5);
		}
	}

	@Override
	public void close() {
		if (logger.isInfoEnabled()) logger.info("Closing nvd river");
		closed = true; // will be used in inner class to break out of the threading
										// loop
		bulkProcessor.close();
		if (threads != null) {
			for (Thread thread : threads) {
				if (thread != null) {
					thread.interrupt();
				}
			}
		}
	}

	@Override
	public void start() {
		logger.info("Starting NVD XML stream ...");

		createIndex(indexName);
		this.bulkProcessor = createBulkProcessor();

		// create one thread per NVD XML stream to fetch
		threads = new ArrayList<Thread>(nvdEntries.size());
		int threadNumber = 0;
		for (NvdEntry nvdEntry : nvdEntries) {
			Thread thread = EsExecutors.daemonThreadFactory(
					settings.globalSettings(), "nvd_fetcher" + threadNumber++).newThread(
					new NvdParser(nvdEntry));
			threads.add(thread);
			thread.start();
		}

	}

	/**
	 * Creates an index with a given name. It tolerates that the index already exists.
	 * 
	 * @param name
	 *          the name of the index to create
	 */
	private void createIndex(String name) {
		try {
			client.admin().indices().prepareCreate(name).execute().actionGet();
		} catch (Exception e) {
			if (ExceptionsHelper.unwrapCause(e) instanceof IndexAlreadyExistsException) {
				// that's fine
			} else {
				logger.warn("failed to create index [{}], disabling river...", e,
						indexName);
				return;
			}
		}
	}

	private BulkProcessor createBulkProcessor() {

		return BulkProcessor
				.builder(client, new Listener() {
					@Override
					public void beforeBulk(long executionId, BulkRequest request) {
						logger.debug("Going to execute new bulk composed of {} actions",
								request.numberOfActions());
					}

					@Override
					public void afterBulk(long executionId, BulkRequest request,
							BulkResponse response) {
						logger.debug("Executed bulk composed of {} actions",
								request.numberOfActions());
						if (response.hasFailures()) {
							logger.warn("There was failures while executing bulk",
									response.buildFailureMessage());
							if (logger.isDebugEnabled()) {
								for (BulkItemResponse item : response.getItems()) {
									if (item.isFailed()) {
										logger.debug("Error for {}/{}/{} for {} operation: {}",
												item.getIndex(), item.getType(), item.getId(),
												item.getOpType(), item.getFailureMessage());
									}
								}
							}
						}
					}

					@Override
					public void afterBulk(long executionId, BulkRequest request,
							Throwable t) {
						logger.debug("Executed bulk composed of {} actions",
								request.numberOfActions());
						logger.warn("There were failures while executing bulk: ",
								t.getMessage());
					}

				}).setBulkActions(bulkSize).setConcurrentRequests(maxConcurrentBulk)
				.setFlushInterval(bulkFlushInterval).build();
	}

	/**
	 * Implements a simple XML parser for NVD CVE entries based on JAXB and also uses JAXB
	 * to convert CVE entries to JSON.
	 * 
	 * @author Florian Rosenberg
	 */
	private class NvdParser implements Runnable {

		private static final String	CVE_TYPE	= "cve";
		private NvdEntry						nvdEntry;

		public NvdParser(NvdEntry nvdEntry) {
			this.nvdEntry = nvdEntry;
		}

		@Override
		public void run() {
			while (true) {
				if (closed) { return; }
				URL resource = null;
				JAXBContext jaxbContext = null;
				try {
					resource = new URL(nvdEntry.getUrl());
					logger.debug("Parsing " + resource);

					// parse NVD XML from and produce JAXB object model
					jaxbContext = JAXBContext.newInstance(Nvd.class);
					Unmarshaller um = jaxbContext.createUnmarshaller();
					Nvd nvd = (Nvd) um.unmarshal(resource.openStream());
					String nvdName = nvdEntry.getName();

					Date lastModifiedHttpResource = getHttpHeadDate(resource);
					logger.info("Last-modified from HTTP HEAD: {}",
							lastModifiedHttpResource);

					Date lastModifiedStreamInRiver = getLastDateFromRiver(nvdEntry
							.getName());
					logger.info("Last-modified as set in stream: {}",
							lastModifiedStreamInRiver);

					// only insert if it has never been inserted or if the stream is newer
					if (lastModifiedStreamInRiver == null
							|| lastModifiedHttpResource.after(lastModifiedStreamInRiver)) {
						logger.info("Inserting {} CVE entries ...", nvd.getEntry().size());
						String id = null;
						for (VulnerabilityType entry : nvd.getEntry()) {
							id = entry.getId();

							bulkProcessor.add(indexRequest(indexName).type(CVE_TYPE).id(id)
									.source(toJson(entry, riverName.getName(), nvdName)));

							if (logger.isDebugEnabled()) logger.debug(
									"NvdEntry update detected for source [{}]",
									nvdName != null ? nvdName : "undefined");
							if (logger.isTraceEnabled()) logger.trace("NvdEntry is : {}",
									entry.toString());
						}
					}

					updateLastModifiedInStream(nvdEntry.getName(),
							lastModifiedHttpResource);

					logger.info("NVD fetcher thread is sleeping for '{}' minutes",
							nvdEntry.getUpdateRate().getMinutes());
					Thread.sleep(nvdEntry.getUpdateRate().getMillis());

				} catch (JAXBException e) {
					logger
							.warn("Error during JAXB processing URL from '%s'", e, resource);
				} catch (MalformedURLException e) {
					logger.warn("Error while processing the NVD feed URL from '%s'", e,
							resource);
				} catch (IOException e) {
					logger.warn("Error while reading from '%s'", e, resource);
				} catch (InterruptedException e) {
					logger.warn("Thread '{}' was interrupted", e, Thread.currentThread()
							.getId());
				}
			}
		}

		/**
		 * Update the last_update (date field) in the river setting for a particular XML
		 * stream.
		 * 
		 * @param streamName
		 * @param lastModifiedHttpResource
		 */
		@SuppressWarnings("unchecked")
		private void updateLastModifiedInStream(String streamName,
				Date lastModifiedHttpResource) {

			// update settings with 'last_update' field
			Map<String, List<?>> nvd = (Map<String, List<?>>) settings.settings()
					.get(NVD_TYPE);
			List<?> streams = (List<?>) nvd.get("streams");
			for (Object o : streams) {
				Map<String, String> stream = (Map<String, String>) o;
				if (stream.get("name").equals(streamName)) {
					SimpleDateFormat dateFormat = new SimpleDateFormat(
							"EEE, dd MMM yyyy HH:mm:ss z", Locale.US);
					dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
					stream
							.put("last_update", dateFormat.format(lastModifiedHttpResource));
				}
			}

			// update the settings
			bulkProcessor.add(indexRequest("_river").type(riverName.name())
					.id("_meta").source(nvd));
		}

		/**
		 * Retrieves the HTTP Last-Modified header from the given URL.
		 */
		private Date getHttpHeadDate(URL resource) throws IOException {
			URLConnection conn = resource.openConnection();
			String lastModified = conn.getHeaderField("Last-Modified");
			logger.info("Resource [{}] was last modified on [{}]",
					resource.toString(), lastModified);

			SimpleDateFormat dateFormat = new SimpleDateFormat(
					"EEE, dd MMM yyyy HH:mm:ss z", Locale.US);
			dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
			try {
				return dateFormat.parse(lastModified);
			} catch (ParseException e) {
				System.out.println("SAU did not parse");
				logger.warn("Cannot parse last modified date [{}]", e, lastModified);
				return null;
			}
		}

		/**
		 * Converts a {@link VulnerabilityType} entry to JSON.
		 * 
		 * @param entry
		 * @param name
		 * @param nvdNam
		 * @return the JSON representation as string
		 * @throws JAXBException
		 */
		private String toJson(VulnerabilityType entry, String name, String nvdName)
				throws JAXBException {

			Map<String, Object> properties = new HashMap<String, Object>(2);
			properties.put(JAXBContextProperties.MEDIA_TYPE, "application/json");
			properties.put(JAXBContextProperties.JSON_INCLUDE_ROOT, false);

			// convert a single CVE entry to JSON
			JAXBContext jc = JAXBContext.newInstance(
					new Class[] { VulnerabilityType.class }, properties);
			Marshaller marshaller = jc.createMarshaller();
			// marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
			StringWriter swriter = new StringWriter();
			marshaller.marshal(entry, swriter);
			return swriter.toString();
		}

		@SuppressWarnings("unchecked")
		private Date getLastDateFromRiver(String nvdStreamName) {
			client.admin().indices().prepareRefresh("_river").execute().actionGet();
			GetResponse resp = client
					.prepareGet("_river", riverName().name(), "_meta").execute()
					.actionGet();
			if (resp.isExists()) {
				Map<String, List<?>> nvd = (Map<String, List<?>>) resp.getSourceAsMap()
						.get(NVD_TYPE);

				if (nvd != null) {
					List<?> streams = (List<?>) nvd.get("streams");
					for (Object o : streams) {
						Map<String, String> stream = (Map<String, String>) o;
						String lastUpdate = stream.get("last_update");
						if (lastUpdate != null) { return ISODateTimeFormat
								.dateOptionalTimeParser().parseDateTime(lastUpdate).toDate(); }
						logger.warn("last_update field not present in stream [{}].",
								stream.get("name"));
						return null;
					}
				}
			}
			return null;
		}
	}

}
