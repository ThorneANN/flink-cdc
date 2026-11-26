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

package org.apache.flink.cdc.connectors.sqlserver.source.utils;

import org.apache.flink.table.catalog.ObjectPath;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Tests the shared SQL Server table chunk-key syntax. */
class SqlServerChunkKeyColumnParserTest {

    @Test
    void parsesMultipleTablesAndTrailingSeparator() {
        assertThat(
                        SqlServerChunkKeyColumnParser.parseObjectPaths(
                                " dbo.orders : order_id ; dbo.users:user_id; "))
                .containsExactlyInAnyOrderEntriesOf(
                        Map.of(
                                new ObjectPath("dbo", "orders"), "order_id",
                                new ObjectPath("dbo", "users"), "user_id"));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "inventory.dbo.(?:orders|users)",
                "inventory.dbo.(?i:orders)",
                "inventory.dbo.[a:b]+",
                "inventory.dbo.[[a:b]:c]+",
                "inventory.dbo.[]:a]+",
                "inventory.dbo.\\Qorders:archive;v1\\E"
            })
    void preservesColonsAndSemicolonsInsideTablePatterns(String pattern) {
        assertThat(
                        SqlServerChunkKeyColumnParser.parse(
                                pattern + ":tenant:id;inventory.dbo.other:id"))
                .containsExactlyInAnyOrderEntriesOf(
                        Map.of(pattern, "tenant:id", "inventory.dbo.other", "id"));
    }

    @Test
    void preservesEscapedIdentifierCharacters() {
        assertThat(
                        SqlServerChunkKeyColumnParser.parseObjectPaths(
                                "sales\\.v1.orders\\:2026\\;archive:tenant:id\\;part]"))
                .containsExactlyInAnyOrderEntriesOf(
                        Map.of(
                                new ObjectPath("sales.v1", "orders:2026;archive"),
                                "tenant:id;part]"));
        assertThat(SqlServerChunkKeyColumnParser.parseObjectPaths("dbo.orders:tenant\\\\id"))
                .containsEntry(new ObjectPath("dbo", "orders"), "tenant\\id");
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "",
                " ",
                ";dbo.orders:id",
                "dbo.orders",
                ":id",
                "dbo.orders:",
                "dbo.orders:id;" + ";dbo.users:id",
                "dbo.(?:orders:id",
                "dbo.[a:b:id",
                "dbo.orders:id\\"
            })
    void rejectsMalformedMappings(String value) {
        assertThatThrownBy(() -> SqlServerChunkKeyColumnParser.parse(value))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "orders:id",
                "inventory.dbo.orders:id",
                ".dbo.orders:id",
                "dbo.orders.:id",
                "dbo..orders:id",
                "dbo. :id"
            })
    void requiresSchemaAndTableForJavaPaths(String value) {
        assertThatThrownBy(() -> SqlServerChunkKeyColumnParser.parseObjectPaths(value))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("schema.table");
    }

    @Test
    void rejectsDuplicateTableEntries() {
        assertThatThrownBy(() -> SqlServerChunkKeyColumnParser.parse("dbo.orders:id;dbo.orders:id"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Duplicate");
    }

    @Test
    void rejectsNullMappings() {
        assertThatThrownBy(() -> SqlServerChunkKeyColumnParser.parse(null))
                .isInstanceOf(NullPointerException.class);
    }
}
