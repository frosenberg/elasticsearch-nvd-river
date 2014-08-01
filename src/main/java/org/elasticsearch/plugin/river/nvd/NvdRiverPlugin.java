package org.elasticsearch.plugin.river.nvd;

import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.inject.Module;
import org.elasticsearch.plugins.AbstractPlugin;
import org.elasticsearch.river.RiversModule;
import org.elasticsearch.river.nvd.NvdRiverModule;

/**
 * @author Florian Rosenberg
 */
public class NvdRiverPlugin extends AbstractPlugin {

	@Inject
	public NvdRiverPlugin() {
	}

	@Override
	public String name() {
		return "river-nvd";
	}

	@Override
	public String description() {
		return "River NVD Plugin";
	}

	@Override
	public void processModule(Module module) {
		if (module instanceof RiversModule) {
			((RiversModule) module).registerRiver("nvd", NvdRiverModule.class);
		}
	}
}
