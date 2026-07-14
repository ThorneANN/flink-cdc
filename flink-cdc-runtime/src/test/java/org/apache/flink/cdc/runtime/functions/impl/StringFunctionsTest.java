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

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** Unit tests for {@link StringFunctions#toJson}. */
class StringFunctionsTest {

    @Test
    void testToJsonNull() {
        Assertions.assertThat(StringFunctions.toJson(null)).isNull();
    }

    @Test
    void testToJsonBoolean() {
        Assertions.assertThat(StringFunctions.toJson(true)).isEqualTo("true");
        Assertions.assertThat(StringFunctions.toJson(false)).isEqualTo("false");
    }

    @Test
    void testToJsonInteger() {
        Assertions.assertThat(StringFunctions.toJson(42)).isEqualTo("42");
        Assertions.assertThat(StringFunctions.toJson(0)).isEqualTo("0");
        Assertions.assertThat(StringFunctions.toJson(-1)).isEqualTo("-1");
    }

    @Test
    void testToJsonLong() {
        Assertions.assertThat(StringFunctions.toJson(9876543210L)).isEqualTo("9876543210");
    }

    @Test
    void testToJsonDouble() {
        Assertions.assertThat(StringFunctions.toJson(3.14d)).isEqualTo("3.14");
    }

    @Test
    void testToJsonBigDecimal() {
        Assertions.assertThat(StringFunctions.toJson(new BigDecimal("123.45"))).isEqualTo("123.45");
    }

    @Test
    void testToJsonString() {
        Assertions.assertThat(StringFunctions.toJson("hello")).isEqualTo("\"hello\"");
    }

    @Test
    void testToJsonStringWithSpecialChars() {
        Assertions.assertThat(StringFunctions.toJson("say \"hi\"")).isEqualTo("\"say \\\"hi\\\"\"");
        Assertions.assertThat(StringFunctions.toJson("a\\b")).isEqualTo("\"a\\\\b\"");
        Assertions.assertThat(StringFunctions.toJson("line1\nline2"))
                .isEqualTo("\"line1\\nline2\"");
        Assertions.assertThat(StringFunctions.toJson("tab\there")).isEqualTo("\"tab\\there\"");
    }

    @Test
    void testToJsonEmptyString() {
        Assertions.assertThat(StringFunctions.toJson("")).isEqualTo("\"\"");
    }

    @Test
    void testToJsonList() {
        Assertions.assertThat(StringFunctions.toJson(Arrays.asList(1, 2, 3))).isEqualTo("[1,2,3]");
    }

    @Test
    void testToJsonEmptyList() {
        Assertions.assertThat(StringFunctions.toJson(Collections.emptyList())).isEqualTo("[]");
    }

    @Test
    void testToJsonListOfStrings() {
        Assertions.assertThat(StringFunctions.toJson(Arrays.asList("a", "b")))
                .isEqualTo("[\"a\",\"b\"]");
    }

    @Test
    void testToJsonMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("key", "value");
        Assertions.assertThat(StringFunctions.toJson(map)).isEqualTo("{\"key\":\"value\"}");
    }

    @Test
    void testToJsonEmptyMap() {
        Assertions.assertThat(StringFunctions.toJson(Collections.emptyMap())).isEqualTo("{}");
    }

    @Test
    void testToJsonNestedMapInList() {
        Map<String, Object> inner = new LinkedHashMap<>();
        inner.put("x", 1);
        Assertions.assertThat(StringFunctions.toJson(Collections.singletonList(inner)))
                .isEqualTo("[{\"x\":1}]");
    }

    @Test
    void testToJsonListInMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("arr", Arrays.asList(1, 2));
        Assertions.assertThat(StringFunctions.toJson(map)).isEqualTo("{\"arr\":[1,2]}");
    }

    @Test
    void testToJsonListWithNull() {
        Assertions.assertThat(StringFunctions.toJson(Arrays.asList(1, null, 3)))
                .isEqualTo("[1,null,3]");
    }

    @Test
    void testToJsonFallbackToString() {
        // LocalDate has no special handling — should fall back to quoted toString()
        LocalDate date = LocalDate.of(2024, 1, 15);
        Assertions.assertThat(StringFunctions.toJson(date)).isEqualTo("\"2024-01-15\"");
    }
}
