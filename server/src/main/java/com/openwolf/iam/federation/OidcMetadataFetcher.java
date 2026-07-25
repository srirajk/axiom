package com.openwolf.iam.federation;

import java.net.URI;

public interface OidcMetadataFetcher {
    OidcMetadata fetch(URI discoveryUri);
}
