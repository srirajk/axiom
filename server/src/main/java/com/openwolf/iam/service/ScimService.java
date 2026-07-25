package com.openwolf.iam.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.openwolf.iam.entity.Group;
import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.entity.ScimProvisioningSource;
import com.openwolf.iam.entity.ScimResourceLink;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.GroupRepository;
import com.openwolf.iam.repository.PrincipalRepository;
import com.openwolf.iam.repository.ScimResourceLinkRepository;
import com.openwolf.iam.scim.ScimException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
@Transactional
public class ScimService {
    private static final String USER = "User";
    private static final String GROUP = "Group";
    private static final String USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
    private static final String GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group";
    private static final Pattern EQ = Pattern.compile("(?i)^externalId\\s+eq\\s+\\\"([^\\\"]+)\\\"$");
    private final PrincipalRepository principals;
    private final GroupRepository groups;
    private final ScimResourceLinkRepository links;
    private final ObjectMapper mapper;
    private final PasswordEncoder passwordEncoder;
    private final AuditService audit;

    public ScimService(PrincipalRepository principals, GroupRepository groups, ScimResourceLinkRepository links,
                       ObjectMapper mapper, PasswordEncoder passwordEncoder, AuditService audit) {
        this.principals = principals; this.groups = groups; this.links = links; this.mapper = mapper;
        this.passwordEncoder = passwordEncoder; this.audit = audit;
    }

    @Transactional(readOnly = true)
    public ObjectNode discovery(String kind) {
        ObjectNode value = mapper.createObjectNode();
        if ("config".equals(kind)) {
            value.putArray("schemas").add("urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig");
            value.putObject("patch").put("supported", true);
            value.putObject("bulk").put("supported", false).put("maxOperations", 0).put("maxPayloadSize", 0);
            value.putObject("filter").put("supported", true).put("maxResults", 100);
            value.putObject("changePassword").put("supported", false);
            value.putObject("sort").put("supported", false);
            value.putObject("etag").put("supported", true);
            value.putArray("authenticationSchemes").addObject().put("type", "oauth2BearerToken").put("name", "SCIM bearer credential").put("description", "Source-scoped selector and secret bearer credential");
            return value;
        }
        if ("resourceTypes".equals(kind)) {
            ArrayNode resources = value.putArray("resources");
            resources.addObject().put("id", "User").put("name", "User").put("endpoint", "/scim/v2/Users").putArray("schemaExtensions");
            resources.addObject().put("id", "Group").put("name", "Group").put("endpoint", "/scim/v2/Groups").putArray("schemaExtensions");
            value.putArray("schemas").add("urn:ietf:params:scim:api:messages:2.0:ListResponse"); return value;
        }
        value.putArray("schemas").add("urn:ietf:params:scim:api:messages:2.0:ListResponse");
        ArrayNode schemas = value.putArray("Resources");
        schemas.addObject().put("id", USER_SCHEMA).put("name", "User").put("description", "Core User schema");
        schemas.addObject().put("id", GROUP_SCHEMA).put("name", "Group").put("description", "Core Group schema");
        return value;
    }

    public Mutation create(ScimProvisioningSource source, String type, JsonNode body, HttpServletRequest request) {
        String externalId = text(body, "externalId");
        if (externalId == null) throw bad("externalId is required");
        var existing = links.findBySourceIdAndResourceTypeAndExternalId(source.getId(), type, externalId);
        if (existing.isPresent()) return new Mutation(resource(source, existing.get()), false);
        ScimResourceLink link;
        ObjectNode resource;
        if (USER.equals(type)) {
            String username = required(body, "userName");
            Principal principal = new Principal("scim-" + UUID.randomUUID(), source.getTenantId(), username,
                    email(body), passwordEncoder.encode(UUID.randomUUID().toString()), active(body), attributes(body, "displayName", "name", "emails"));
            principal.setScimSourceId(source.getId()); principal.setScimManagedFields("[\"userName\",\"active\",\"emails\",\"displayName\",\"name\"]");
            principals.save(principal); link = new ScimResourceLink(source.getId(), source.getTenantId(), type, externalId, principal.getId(), principal.getScimManagedFields());
            links.save(link); resource = userResource(principal, link);
        } else if (GROUP.equals(type)) {
            Group group = new Group(source.getTenantId(), required(body, "displayName"), null, null, "{}");
            group.setScimSourceId(source.getId()); group.setScimManagedFields("[\"displayName\",\"members\"]");
            applyGroupMembers(source, group, body.get("members")); groups.save(group); link = new ScimResourceLink(source.getId(), source.getTenantId(), type, externalId, group.getId().toString(), group.getScimManagedFields());
            links.save(link); resource = groupResource(group, link);
        } else throw bad("Unsupported SCIM resource type");
        audit.logRequired(source.getTenantId(), "scim", "SCIM_CREATE", type, link.getResourceId(), null, resource, correlation(request));
        return new Mutation(resource, true);
    }

    @Transactional(readOnly = true)
    public ObjectNode get(ScimProvisioningSource source, String type, String resourceId) { return resource(source, requireLink(source, type, resourceId)); }

    @Transactional(readOnly = true)
    public ObjectNode list(ScimProvisioningSource source, String type, int startIndex, int count, String filter,
                           String sortBy, String sortOrder) {
        validatePaging(startIndex, count); if (sortBy != null || sortOrder != null) throw bad("sort is not supported");
        String externalId = filterValue(filter);
        Page<ScimResourceLink> page = externalId == null
                ? links.findBySourceIdAndResourceType(source.getId(), type, PageRequest.of(0, Math.min(10000, startIndex - 1 + count), Sort.by("resourceId").ascending()))
                : links.findBySourceIdAndResourceTypeAndExternalId(source.getId(), type, externalId, PageRequest.of(0, 100));
        List<ScimResourceLink> all = page.getContent();
        int from = Math.min(startIndex - 1, all.size());
        int to = Math.min(from + count, all.size());
        ArrayNode resources = mapper.createArrayNode();
        for (ScimResourceLink link : all.subList(from, to)) resources.add(resource(source, link));
        ObjectNode result = mapper.createObjectNode(); result.putArray("schemas").add("urn:ietf:params:scim:api:messages:2.0:ListResponse");
        result.put("totalResults", page.getTotalElements()); result.put("startIndex", startIndex); result.put("itemsPerPage", resources.size()); result.set("Resources", resources); return result;
    }

    public Mutation replace(ScimProvisioningSource source, String type, String resourceId, JsonNode body, String ifMatch, HttpServletRequest request) {
        ScimResourceLink link = requireLink(source, type, resourceId); checkIfMatch(link, ifMatch);
        if (USER.equals(type)) {
            Principal principal = principals.findByIdAndTenantId(resourceId, source.getTenantId()).orElseThrow(() -> bad("SCIM resource not found"));
            principal.setUsername(required(body, "userName")); principal.setEmail(email(body)); principal.setActive(active(body)); updateAttributes(principal, body, "displayName", "name", "emails"); principals.save(principal);
        } else {
            Group group = group(resourceId, source); group.setName(required(body, "displayName")); group.getMembers().clear(); applyGroupMembers(source, group, body.get("members")); groups.save(group);
        }
        link.bump(link.getManagedFields()); links.save(link); ObjectNode resource = resource(source, link); audit.logRequired(source.getTenantId(), "scim", "SCIM_REPLACE", type, resourceId, null, resource, correlation(request)); return new Mutation(resource, false);
    }

    public Mutation patch(ScimProvisioningSource source, String type, String resourceId, JsonNode body, String ifMatch, HttpServletRequest request) {
        ScimResourceLink link = requireLink(source, type, resourceId); checkIfMatch(link, ifMatch);
        JsonNode operations = body.get("Operations"); if (operations == null || !operations.isArray()) throw bad("Operations is required");
        if (USER.equals(type)) patchUser(source, resourceId, operations); else patchGroup(source, resourceId, operations);
        link.bump(link.getManagedFields()); links.save(link); ObjectNode resource = resource(source, link); audit.logRequired(source.getTenantId(), "scim", "SCIM_PATCH", type, resourceId, null, resource, correlation(request)); return new Mutation(resource, false);
    }

    private void patchUser(ScimProvisioningSource source, String id, JsonNode operations) {
        Principal p = principals.findByIdAndTenantId(id, source.getTenantId()).orElseThrow(() -> bad("SCIM resource not found"));
        for (JsonNode op : operations) { String path = required(op, "path"); String action = required(op, "op").toLowerCase(); JsonNode value = op.get("value");
            if (!List.of("replace", "add").contains(action)) throw bad("Only add and replace are supported for User");
            switch (path) { case "active" -> p.setActive(value != null && value.asBoolean()); case "userName" -> p.setUsername(value == null ? null : value.asText()); case "displayName", "name", "emails" -> updateAttribute(p, path, value); default -> throw bad("Unsupported User PATCH path: " + path); }
        } principals.save(p);
    }
    private void patchGroup(ScimProvisioningSource source, String id, JsonNode operations) {
        Group g = group(id, source);
        for (JsonNode op : operations) { String path = required(op, "path"); String action = required(op, "op").toLowerCase(); JsonNode value = op.get("value");
            if ("displayName".equals(path) && List.of("replace", "add").contains(action)) g.setName(value.asText());
            else if ("members".equals(path) && List.of("replace", "add", "remove").contains(action)) {
                if ("replace".equals(action)) { g.getMembers().clear(); applyGroupMembers(source, g, value); }
                else if ("add".equals(action)) applyGroupMembers(source, g, value);
                else removeGroupMembers(source, g, value);
            } else throw bad("Unsupported Group PATCH path: " + path);
        } groups.save(g);
    }
    private void applyGroupMembers(ScimProvisioningSource source, Group group, JsonNode members) { if (members == null || !members.isArray()) return; for (JsonNode member : members) { String id = text(member, "value"); if (id == null || links.findBySourceIdAndResourceTypeAndResourceId(source.getId(), USER, id).isEmpty()) throw bad("Group member must reference a User from this source"); Principal principal = principals.findByIdAndTenantId(id, source.getTenantId()).orElseThrow(() -> bad("SCIM group member not found")); group.getMembers().add(principal); } }
    private void removeGroupMembers(ScimProvisioningSource source, Group group, JsonNode members) { if (members == null || !members.isArray()) return; for (JsonNode member : members) { String id = text(member, "value"); group.getMembers().removeIf(p -> p.getId().equals(id)); } }
    private ObjectNode resource(ScimProvisioningSource source, ScimResourceLink link) { return USER.equals(link.getResourceType()) ? userResource(principals.findByIdAndTenantId(link.getResourceId(), source.getTenantId()).orElseThrow(() -> bad("SCIM resource not found")), link) : groupResource(group(link.getResourceId(), source), link); }
    private ObjectNode userResource(Principal p, ScimResourceLink link) { requireOwnership(p.getScimSourceId(), link.getSourceId()); ObjectNode out = mapper.createObjectNode(); out.putArray("schemas").add(USER_SCHEMA); out.put("id", p.getId()).put("externalId", link.getExternalId()).put("userName", p.getUsername()).put("active", p.isActive()); Map<String, Object> attrs = parse(p.getAttributes()); copyText(out, attrs, "displayName"); if (attrs.get("name") != null) out.set("name", mapper.valueToTree(attrs.get("name"))); if (attrs.get("emails") != null) out.set("emails", mapper.valueToTree(attrs.get("emails"))); meta(out, link); return out; }
    private ObjectNode groupResource(Group g, ScimResourceLink link) { requireOwnership(g.getScimSourceId(), link.getSourceId()); ObjectNode out = mapper.createObjectNode(); out.putArray("schemas").add(GROUP_SCHEMA); out.put("id", g.getId().toString()).put("externalId", link.getExternalId()).put("displayName", g.getName()); ArrayNode members = out.putArray("members"); g.getMembers().forEach(p -> members.addObject().put("value", p.getId()).put("display", p.getUsername())); meta(out, link); return out; }
    private void meta(ObjectNode out, ScimResourceLink link) { ObjectNode meta = out.putObject("meta"); meta.put("resourceType", link.getResourceType()); meta.put("version", etag(link)); meta.put("created", link.getCreatedAt().toString()); meta.put("lastModified", link.getUpdatedAt().toString()); }
    private String etag(ScimResourceLink link) { return Long.toString(link.getVersion()); }
    private ScimResourceLink requireLink(ScimProvisioningSource source, String type, String id) { return links.findBySourceIdAndResourceTypeAndResourceId(source.getId(), type, id).orElseThrow(() -> new ScimException(404, "SCIM resource not found")); }
    private Group group(String id, ScimProvisioningSource source) { try { return groups.findByIdAndTenantId(UUID.fromString(id), source.getTenantId()).orElseThrow(() -> bad("SCIM resource not found")); } catch (IllegalArgumentException ex) { throw bad("SCIM resource not found"); } }
    private void checkIfMatch(ScimResourceLink link, String value) { if (value == null || (!"*".equals(value) && !value.replace("\"", "").equals(etag(link)))) throw new ScimException(412, "If-Match does not match the current resource version"); }
    private String filterValue(String filter) { if (filter == null || filter.isBlank()) return null; Matcher matcher = EQ.matcher(filter.trim()); if (!matcher.matches()) throw bad("Only eq filters on externalId are supported"); return matcher.group(1); }
    private void validatePaging(int start, int count) { if (start < 1 || start > 10000 || count < 1 || count > 100) throw bad("startIndex must be 1..10000 and count must be 1..100"); }
    private static ScimException bad(String message) { return new ScimException(400, message); }
    private static String required(JsonNode node, String field) { String value = text(node, field); if (value == null) throw bad(field + " is required"); return value; }
    private static String text(JsonNode node, String field) { JsonNode value = node == null ? null : node.get(field); return value == null || value.isNull() || !value.isValueNode() || value.asText().isBlank() ? null : value.asText(); }
    private static boolean active(JsonNode node) { return !node.has("active") || node.get("active").asBoolean(); }
    private static String email(JsonNode node) { JsonNode emails = node.get("emails"); if (emails != null && emails.isArray() && emails.size() > 0) return text(emails.get(0), "value"); return null; }
    private String attributes(JsonNode body, String... fields) { Map<String, Object> values = new LinkedHashMap<>(); for (String field : fields) if (body.has(field)) values.put(field, mapper.convertValue(body.get(field), Object.class)); return write(values); }
    private void updateAttributes(Principal p, JsonNode body, String... fields) { Map<String, Object> attrs = parse(p.getAttributes()); for (String field : fields) if (body.has(field)) attrs.put(field, mapper.convertValue(body.get(field), Object.class)); p.setAttributes(write(attrs)); }
    private void updateAttribute(Principal p, String field, JsonNode value) { Map<String, Object> attrs = parse(p.getAttributes()); attrs.put(field, mapper.convertValue(value, Object.class)); p.setAttributes(write(attrs)); }
    private Map<String, Object> parse(String json) { try { return mapper.readValue(json == null || json.isBlank() ? "{}" : json, LinkedHashMap.class); } catch (Exception ex) { throw new ScimException(500, "Stored identity attributes are invalid"); } }
    private String write(Object value) { try { return mapper.writeValueAsString(value); } catch (Exception ex) { throw new ScimException(500, "Could not serialize SCIM resource"); } }
    private static void requireOwnership(UUID entitySourceId, UUID sourceId) { if (!sourceId.equals(entitySourceId)) throw new ScimException(404, "SCIM resource not found"); }
    private static void copyText(ObjectNode out, Map<String, Object> attrs, String field) { Object value = attrs.get(field); if (value != null) out.put(field, String.valueOf(value)); }
    private static String correlation(HttpServletRequest request) { return request == null ? null : request.getHeader("X-Correlation-ID"); }
    public record Mutation(ObjectNode resource, boolean created) {}
}
