/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.flink.cdc.runtime.functions.impl;

import org.apache.flink.cdc.common.types.variant.BinaryVariantInternalBuilder;
import org.apache.flink.cdc.common.types.variant.Variant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** String built-in functions. */
public class StringFunctions {

    private static final Logger LOG = LoggerFactory.getLogger(StringFunctions.class);

    public static int charLength(String str) {
        return str.length();
    }

    public static String trim(String symbol, String target, String str) {
        return str.trim();
    }

    /**
     * Returns a string resulting from replacing all substrings that match the regular expression
     * with replacement.
     */
    public static String regexpReplace(String str, String regex, String replacement) {
        if (str == null || regex == null || replacement == null) {
            return null;
        }
        try {
            return str.replaceAll(regex, Matcher.quoteReplacement(replacement));
        } catch (Exception e) {
            LOG.error(
                    String.format(
                            "Exception in regexpReplace('%s', '%s', '%s')",
                            str, regex, replacement),
                    e);
            // return null if exception in regex replace
            return null;
        }
    }

    public static String concat(String... str) {
        return String.join("", str);
    }

    public static boolean like(String str, String regex) {
        return Pattern.compile(regex).matcher(str).find();
    }

    public static boolean notLike(String str, String regex) {
        return !like(str, regex);
    }

    public static String substr(String str, int beginIndex) {
        return substring(str, beginIndex);
    }

    public static String substr(String str, int beginIndex, int length) {
        return substring(str, beginIndex, length);
    }

    public static String substring(String str, int beginIndex) {
        return substring(str, beginIndex, Integer.MAX_VALUE);
    }

    public static String substring(String str, int beginIndex, int length) {
        if (length < 0) {
            LOG.error(
                    "length of 'substring(str, beginIndex, length)' must be >= 0 and Int type, but length = {}",
                    length);
            throw new RuntimeException(
                    "length of 'substring(str, beginIndex, length)' must be >= 0 and Int type, but length = "
                            + length);
        }
        if (length > Integer.MAX_VALUE || beginIndex > Integer.MAX_VALUE) {
            LOG.error(
                    "length or start of 'substring(str, beginIndex, length)' must be Int type, but length = {}, beginIndex = {}",
                    beginIndex,
                    length);
            throw new RuntimeException(
                    "length or start of 'substring(str, beginIndex, length)' must be Int type, but length = "
                            + beginIndex
                            + ", beginIndex = "
                            + length);
        }
        if (str.isEmpty()) {
            return "";
        }

        int startPos;
        int endPos;

        if (beginIndex > 0) {
            startPos = beginIndex - 1;
            if (startPos >= str.length()) {
                return "";
            }
        } else if (beginIndex < 0) {
            startPos = str.length() + beginIndex;
            if (startPos < 0) {
                return "";
            }
        } else {
            startPos = 0;
        }

        if ((str.length() - startPos) < length) {
            endPos = str.length();
        } else {
            endPos = startPos + length;
        }
        return str.substring(startPos, endPos);
    }

    public static String upper(String str) {
        return str.toUpperCase();
    }

    public static String lower(String str) {
        return str.toLowerCase();
    }

    public static String uuid() {
        return UUID.randomUUID().toString();
    }

    public static String uuid(byte[] b) {
        return UUID.nameUUIDFromBytes(b).toString();
    }

    public static Variant tryParseJson(String jsonStr) {
        return tryParseJson(jsonStr, false);
    }

    public static Variant tryParseJson(String jsonStr, boolean allowDuplicateKeys) {
        if (jsonStr == null || jsonStr.isEmpty()) {
            return null;
        }

        try {
            return BinaryVariantInternalBuilder.parseJson(jsonStr, allowDuplicateKeys);
        } catch (Throwable e) {
            return null;
        }
    }

    /**
     * Serializes a value to its JSON string representation.
     *
     * <p>Type mapping (after {@code JavaObjectConverter.convertToJava}):
     *
     * <ul>
     *   <li>{@code null} → {@code "null"}
     *   <li>{@code Boolean} → {@code "true"} / {@code "false"}
     *   <li>Numeric types ({@code Integer}, {@code Long}, {@code Float}, {@code Double}, {@code
     *       BigDecimal}, etc.) → number literal
     *   <li>{@code String} → quoted, with JSON-escaped special characters
     *   <li>{@code List} → JSON array (recursive)
     *   <li>{@code Map} → JSON object (recursive, keys coerced to strings)
     *   <li>Other types ({@code LocalDate}, {@code LocalDateTime}, etc.) → quoted {@code
     *       toString()}
     * </ul>
     *
     * @param value the Java-layer value to serialize (may be null)
     * @return JSON string, or {@code null} if input is {@code null}
     */
    public static String toJson(Object value) {
        if (value == null) {
            return null;
        }
        return serializeToJson(value);
    }

    private static String serializeToJson(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof Boolean) {
            return value.toString();
        }
        if (value instanceof Integer
                || value instanceof Long
                || value instanceof Short
                || value instanceof Byte
                || value instanceof Float
                || value instanceof Double
                || value instanceof BigDecimal) {
            return value.toString();
        }
        if (value instanceof String) {
            return "\"" + escapeJsonString((String) value) + "\"";
        }
        if (value instanceof List) {
            StringBuilder sb = new StringBuilder("[");
            List<?> list = (List<?>) value;
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) {
                    sb.append(",");
                }
                sb.append(serializeToJson(list.get(i)));
            }
            return sb.append("]").toString();
        }
        if (value instanceof Map) {
            StringBuilder sb = new StringBuilder("{");
            Map<?, ?> map = (Map<?, ?>) value;
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) {
                    sb.append(",");
                }
                sb.append("\"")
                        .append(escapeJsonString(String.valueOf(entry.getKey())))
                        .append("\":")
                        .append(serializeToJson(entry.getValue()));
                first = false;
            }
            return sb.append("}").toString();
        }
        // Fallback: temporal types (LocalDate, LocalDateTime, etc.) and others
        return "\"" + escapeJsonString(value.toString()) + "\"";
    }

    private static String escapeJsonString(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 4);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\b':
                    sb.append("\\b");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    public static Variant parseJson(String jsonStr) {
        return parseJson(jsonStr, false);
    }

    public static Variant parseJson(String jsonStr, boolean allowDuplicateKeys) {
        if (jsonStr == null || jsonStr.isEmpty()) {
            return null;
        }

        try {
            return BinaryVariantInternalBuilder.parseJson(jsonStr, allowDuplicateKeys);
        } catch (Throwable e) {
            throw new IllegalArgumentException(
                    String.format("Failed to parse json string: %s", jsonStr), e);
        }
    }
}
