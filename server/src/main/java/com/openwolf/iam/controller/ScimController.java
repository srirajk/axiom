package com.openwolf.iam.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.openwolf.iam.entity.ScimProvisioningSource;
import com.openwolf.iam.scim.ScimAuthenticationFilter;
import com.openwolf.iam.scim.ScimException;
import com.openwolf.iam.service.ScimService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/scim/v2", produces = "application/scim+json")
public class ScimController {
    private final ScimService service;
    public ScimController(ScimService service) { this.service = service; }

    @GetMapping("/ServiceProviderConfig") public JsonNode config() { return service.discovery("config"); }
    @GetMapping("/ResourceTypes") public JsonNode resourceTypes() { return service.discovery("resourceTypes"); }
    @GetMapping("/Schemas") public JsonNode schemas() { return service.discovery("schemas"); }

    @GetMapping("/{type}") public JsonNode list(@PathVariable String type, @RequestParam(defaultValue = "1") int startIndex,
                                                   @RequestParam(defaultValue = "100") int count, @RequestParam(required = false) String filter,
                                                   @RequestParam(required = false) String sortBy, @RequestParam(required = false) String sortOrder,
                                                   HttpServletRequest request) { return service.list(source(request), normalize(type), startIndex, count, filter, sortBy, sortOrder); }
    @GetMapping("/{type}/{id}") public ResponseEntity<JsonNode> get(@PathVariable String type, @PathVariable String id, HttpServletRequest request) { return response(service.get(source(request), normalize(type), id)); }

    @PostMapping(value = "/{type}", consumes = {MediaType.APPLICATION_JSON_VALUE, "application/scim+json"})
    public ResponseEntity<JsonNode> create(@PathVariable String type, @RequestBody JsonNode body, HttpServletRequest request) {
        ScimService.Mutation result = service.create(source(request), normalize(type), body, request);
        return response(result.resource(), result.created() ? 201 : 200);
    }
    @PutMapping(value = "/{type}/{id}", consumes = {MediaType.APPLICATION_JSON_VALUE, "application/scim+json"})
    public ResponseEntity<JsonNode> replace(@PathVariable String type, @PathVariable String id, @RequestBody JsonNode body,
                                            @RequestHeader(value = "If-Match", required = false) String ifMatch, HttpServletRequest request) { return response(service.replace(source(request), normalize(type), id, body, ifMatch, request).resource()); }
    @PatchMapping(value = "/{type}/{id}", consumes = {MediaType.APPLICATION_JSON_VALUE, "application/scim+json"})
    public ResponseEntity<JsonNode> patch(@PathVariable String type, @PathVariable String id, @RequestBody JsonNode body,
                                          @RequestHeader(value = "If-Match", required = false) String ifMatch, HttpServletRequest request) { return response(service.patch(source(request), normalize(type), id, body, ifMatch, request).resource()); }
    @DeleteMapping("/{type}/{id}")
    public ResponseEntity<Void> deactivate(@PathVariable String type, @PathVariable String id,
                                           @RequestHeader(value = "If-Match", required = false) String ifMatch, HttpServletRequest request) {
        if (!"User".equals(normalize(type))) throw new ScimException(400, "Only Users can be deactivated");
        JsonNode body = service.get(source(request), "User", id).deepCopy(); ((com.fasterxml.jackson.databind.node.ObjectNode) body).put("active", false);
        service.replace(source(request), "User", id, body, ifMatch, request); return ResponseEntity.noContent().build();
    }

    @PostMapping(value = {"/Bulk", "/Users/.search", "/Groups/.search"}, consumes = {MediaType.APPLICATION_JSON_VALUE, "application/scim+json"})
    public ResponseEntity<Void> unsupported() { throw new ScimException(501, "Bulk and POST /.search are not supported"); }

    private ResponseEntity<JsonNode> response(JsonNode body) { return response(body, 200); }
    private ResponseEntity<JsonNode> response(JsonNode body, int status) { String version = body.path("meta").path("version").asText(null); ResponseEntity.BodyBuilder builder = ResponseEntity.status(status).contentType(MediaType.parseMediaType("application/scim+json")); if (version != null) builder.header(HttpHeaders.ETAG, "\"" + version + "\""); return builder.body(body); }
    private static String normalize(String type) { if ("Users".equals(type)) return "User"; if ("Groups".equals(type)) return "Group"; throw new ScimException(404, "SCIM resource type not found"); }
    private static ScimProvisioningSource source(HttpServletRequest request) { Object source = request.getAttribute(ScimAuthenticationFilter.SOURCE_ATTRIBUTE); if (source instanceof ScimProvisioningSource value) return value; throw new ScimException(401, "SCIM bearer credential required"); }
}
