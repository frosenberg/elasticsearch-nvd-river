package org.elasticsearch.river.nvd;

import org.elasticsearch.common.inject.AbstractModule;
import org.elasticsearch.river.River;

public class NvdRiverModule extends AbstractModule {

	@Override
	protected void configure() {
		bind(River.class).to(NvdRiver.class).asEagerSingleton();
	}

}