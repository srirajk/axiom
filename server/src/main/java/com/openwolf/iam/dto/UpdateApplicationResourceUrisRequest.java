package com.openwolf.iam.dto;

import jakarta.validation.constraints.NotNull;
import java.util.List;

public record UpdateApplicationResourceUrisRequest(@NotNull List<String> resourceUris, @NotNull Long expectedRevision) {}
