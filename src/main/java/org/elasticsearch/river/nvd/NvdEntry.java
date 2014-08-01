/*
 * Licensed to David Pilato (the "Author") under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. Author licenses this
 * file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.river.nvd;

import org.elasticsearch.common.unit.TimeValue;

/**
 * An entry in the NVD river definition. Each entry has a name, URL to the CVE file and 
 * an update rate (when it is going to be refreshed). 
 * @author Florian Rosenberg
 *
 */
public class NvdEntry {
	private String name;
	private String url;
	private TimeValue updateRate;

	public NvdEntry(String name, String url, TimeValue updateRate) {
		this.name = name;
		this.url = url;
		this.updateRate = updateRate;
	}

	public String getName() {
		return name;
	}

	public String getUrl() {
		return url;
	}

	public TimeValue getUpdateRate() {
		return updateRate;
	}

}
