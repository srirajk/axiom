package com.openwolf.iam.entity;

import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ScimJsonMappingTest {
    @Test
    void mapsEveryV19ScimJsonbStringToJsonJdbcType() throws Exception {
        Map<Class<?>, String> fields = Map.of(
                Principal.class, "scimManagedFields",
                Group.class, "scimManagedFields",
                ScimResourceLink.class, "managedFields");
        for (Map.Entry<Class<?>, String> entry : fields.entrySet()) {
            Field field = entry.getKey().getDeclaredField(entry.getValue());
            assertThat(field.getAnnotation(JdbcTypeCode.class)).isNotNull();
            assertThat(field.getAnnotation(JdbcTypeCode.class).value()).isEqualTo(SqlTypes.JSON);
        }
    }
}
