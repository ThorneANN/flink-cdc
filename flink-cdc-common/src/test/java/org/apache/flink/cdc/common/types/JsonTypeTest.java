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

package org.apache.flink.cdc.common.types;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Tests for {@link JsonType}. */
class JsonTypeTest {

    @Test
    void testDefaultNullability() {
        JsonType type = DataTypes.JSON();
        assertThat(type.isNullable()).isTrue();
        assertThat(type.getTypeRoot()).isEqualTo(DataTypeRoot.JSON);
    }

    @Test
    void testNotNull() {
        DataType type = DataTypes.JSON().notNull();
        assertThat(type.isNullable()).isFalse();
        assertThat(type).isInstanceOf(JsonType.class);
    }

    @Test
    void testCopy() {
        JsonType original = new JsonType(false);
        DataType nullable = original.copy(true);
        assertThat(nullable.isNullable()).isTrue();
        assertThat(nullable).isInstanceOf(JsonType.class);
        assertThat(nullable).isNotEqualTo(original);
    }

    @Test
    void testSerializableString() {
        assertThat(new JsonType().asSerializableString()).isEqualTo("JSON");
        assertThat(new JsonType(false).asSerializableString()).isEqualTo("JSON NOT NULL");
    }

    @Test
    void testEquality() {
        assertThat(new JsonType()).isEqualTo(new JsonType());
        assertThat(new JsonType(false)).isEqualTo(new JsonType(false));
        assertThat(new JsonType()).isNotEqualTo(new JsonType(false));
    }

    @Test
    void testFamilyMembership() {
        JsonType type = new JsonType();
        assertThat(type.is(DataTypeFamily.EXTENSION)).isTrue();
        assertThat(type.is(DataTypeFamily.PREDEFINED)).isTrue();
        assertThat(type.is(DataTypeFamily.CHARACTER_STRING)).isTrue();
    }

    @Test
    void testVisitorDispatch() {
        DataTypeVisitor<String> visitor =
                new DataTypeDefaultVisitor<String>() {
                    @Override
                    public String visit(JsonType jsonType) {
                        return "json";
                    }

                    @Override
                    protected String defaultMethod(DataType dataType) {
                        return "other";
                    }
                };
        assertThat(new JsonType().accept(visitor)).isEqualTo("json");
    }
}