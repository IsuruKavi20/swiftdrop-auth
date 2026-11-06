package com.swiftdrop.auth.common.privacy;

import java.util.LinkedHashMap;
import java.util.Map;

/** Builds one export entry in a fixed field order; unlike Map.of it keeps null values (shown as null). */
public final class ExportMap {

    private final Map<String, Object> fields = new LinkedHashMap<>();

    private ExportMap() {
    }

    public static ExportMap of() {
        return new ExportMap();
    }

    public ExportMap put(String field, Object value) {
        fields.put(field, value);
        return this;
    }

    public Map<String, Object> build() {
        return fields;
    }
}
