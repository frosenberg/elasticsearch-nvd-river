package org.elasticsearch.river.nvd;

import static org.elasticsearch.common.xcontent.XContentFactory.jsonBuilder;
import static org.hamcrest.Matchers.equalTo;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.concurrent.TimeUnit;

import org.elasticsearch.action.count.CountResponse;
import org.elasticsearch.common.base.Predicate;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.index.query.QueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.test.ElasticsearchIntegrationTest;
import org.junit.After;
import org.junit.Test;

/**
 * @author Florian Rosenberg
 */
@ElasticsearchIntegrationTest.ClusterScope(scope = ElasticsearchIntegrationTest.Scope.SUITE)
public class NvdRiverIntegrationTest extends ElasticsearchIntegrationTest {

	@After
	public void tearDown() throws Exception {
		logger.info("  --> stopping rivers");
		// We need to make sure that the _river is stopped
		cluster().wipeIndices("_river");

		// We have to wait a little because it could throw
		// java.lang.RuntimeException
		Thread.sleep(1000);
		super.tearDown();
	}

	/**
	 * Index vulnerabilites: nvdcve-2.0-modified.xml
	 * @throws URISyntaxException 
	 */
	@Test
	public void testNvdImport1() throws IOException, InterruptedException, URISyntaxException {
		String index = "nvd1";
		startRiver(index, "nvdcve-2.0-modified.xml");
		checkDocsExist(index, 130, 370); // expecting 370 docs
	}
	
	/**
	 * Index vulnerabilites of 2014: nvdcve-2.0-modified.xml
	 * @throws URISyntaxException 
	 */
	@Test
	public void testNvdImport2() throws IOException, InterruptedException, URISyntaxException {
		String index = "nvd2";
		startRiver(index, "nvdcve-2.0-recent.xml");
		checkDocsExist(index, 45, 130); // expecting 130 docs
	}
	
	/**
	 * Creates a river and inserts some data.
	 */
	private XContentBuilder createRiver(String... names)
			throws IOException, URISyntaxException {
		XContentBuilder river = jsonBuilder().prettyPrint().startObject()
				.field("type", "nvd").startObject("nvd");
		
		if (names.length > 0) {
			river.startArray("streams");
			for (String name : names) {
				addLocalRiver(river, name);
			}
			river.endArray();
		}

    river.endObject()
    		 .startObject("index").field("flush_interval", "500ms")
				 .endObject().endObject();

		logger.info("createRiver: {}", river.string());
		return river;
	}

	private void startRiver(final String riverName, String... files) throws InterruptedException, IOException, URISyntaxException {
		logger.info("  --> starting river [{}]", riverName);		
		createIndex(riverName);
    index("_river", riverName, "_meta", createRiver(files));
		refresh();
	}


	private String getUrl(String name) throws IOException, URISyntaxException {
		URL resource = getClass().getResource("/" + name);
		return resource.toURI().toString();		
	}

	private void addLocalRiver(XContentBuilder xcb, String name)
			throws IOException, URISyntaxException {
		addRiver(xcb, getUrl(name), name);
	}

	private void addRiver(XContentBuilder xcb, String url, String name) {
		try {
			xcb.startObject().field("url", url).field("update_rate", 10000);
			if (name != null) {
				xcb.field("name", name);
			}
			xcb.endObject();
		} catch (Exception e) {
			logger.error("fail to add river NVD XML url [{}]", url);
			fail("fail to add river feed");
		}
	}

	private void checkDocsExist(final String index, int timetoWaitInSec, int expectedDocs) throws InterruptedException {
		existSomeDocs(index, null, timetoWaitInSec, expectedDocs);
	}

	private void existSomeDocs(final String index, final String source, int timetoWaitInSec, final int expectedDocs)
			throws InterruptedException {
		
		assertThat("Documents exist",
				awaitBusy(new Predicate<Object>() {
					@Override
					public boolean apply(Object o) {
						QueryBuilder query;
						if (source == null) {
							query = QueryBuilders.matchAllQuery();
						} else {
							query = QueryBuilders.queryString(source).defaultField("id");
						}
						CountResponse response = client().prepareCount(index)
								.setQuery(query).execute().actionGet();
						System.out.println("FLORIAN: " + response.getCount());
						return response.getCount() == expectedDocs;
					}
				}, timetoWaitInSec, TimeUnit.SECONDS), equalTo(true));
	}

}
