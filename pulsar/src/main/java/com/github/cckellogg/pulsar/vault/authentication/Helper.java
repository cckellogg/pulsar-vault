package com.github.cckellogg.pulsar.vault.authentication;

import com.bettercloud.vault.json.JsonObject;
import com.bettercloud.vault.json.JsonValue;

import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

class Helper {
    private Helper() {}

    // secret data keys
    public static final String KeyDataDisplayName = "display_name";
    public static final String KeyDataUsername = "username";
    public static final String KeyDataMeta = "meta";
    public static final String KeyMetaRole = "role";

    static String roleFromResponseData(JsonObject jsonData) {
        if (jsonData == null) {
            return "";
        }
        // do we have any metadata?
        final Map<String, String> meta = parseMap(jsonData.get(KeyDataMeta));
        if (meta.containsKey(KeyMetaRole)) {
            return meta.get(KeyMetaRole);
        }

        return jsonData.getString(KeyDataDisplayName, "");
    }

    public static Map<String, String> parseMap(JsonValue value) {
        if (value == null || value.isNull()) {
            return Collections.emptyMap();
        }
        final Map<String, String> map = new HashMap<>();
        Iterator<JsonObject.Member> var = value.asObject().iterator();
        while(var.hasNext()) {
            JsonObject.Member member = var.next();
            JsonValue jsonValue = member.getValue();
            if (jsonValue != null && !jsonValue.isNull()) {
                if (jsonValue.isString()) {
                    map.put(member.getName(), jsonValue.asString());
                } else {
                    map.put(member.getName(), jsonValue.toString());
                }
            }
        }

        return map;
    }
}
