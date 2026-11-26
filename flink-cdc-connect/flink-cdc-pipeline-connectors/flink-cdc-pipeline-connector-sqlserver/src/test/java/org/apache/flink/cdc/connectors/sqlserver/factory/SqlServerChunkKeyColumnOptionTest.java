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

package org.apache.flink.cdc.connectors.sqlserver.factory;

import org.apache.flink.cdc.common.configuration.Configuration;
import org.apache.flink.cdc.common.event.TableId;
import org.apache.flink.cdc.common.factories.Factory;
import org.apache.flink.cdc.connectors.sqlserver.source.SqlServerDataSource;
import org.apache.flink.cdc.connectors.sqlserver.source.config.SqlServerSourceConfig;

import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.core.type.TypeReference;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Tests SQL Server chunk-key options without requiring a running database. */
class SqlServerChunkKeyColumnOptionTest {

    private static final ObjectMapper YAML_MAPPER = new ObjectMapper(new YAMLFactory());
    private static final String CHUNK_KEY_COLUMN = "scan.incremental.snapshot.chunk.key-column";
    private static final String CHUNK_KEY_MAP =
            "scan.incremental.snapshot.chunk.key-column-by-table";
    private static final String CHUNK_KEY_BY_TABLE = CHUNK_KEY_MAP + ".";

    private static final List<TableId> TABLES =
            Arrays.asList(
                    TableId.tableId("inventory", "dbo", "orders"),
                    TableId.tableId("inventory", "dbo", "users"),
                    TableId.tableId("inventory", "audit", "orders"),
                    TableId.tableId("inventory", "dbo", "products"));

    @ParameterizedTest
    @ValueSource(strings = {"id", "tenant:id", "tenant;id", "inventory.dbo.orders:id"})
    void preservesLegacyColumnName(String columnName) throws Exception {
        SqlServerSourceConfig sourceConfig =
                configureYaml(CHUNK_KEY_COLUMN + ": '" + columnName + "'");

        assertThat(sourceConfig.getChunkKeyColumn()).isEqualTo(columnName);
        assertThat(chunkKey(sourceConfig, "dbo", "orders")).isEqualTo(columnName);
        assertThat(chunkKey(sourceConfig, "audit", "orders")).isEqualTo(columnName);
    }

    @Test
    void parsesTableChunkKeysFromYamlBlockScalar() throws Exception {
        SqlServerSourceConfig sourceConfig =
                configureYaml(
                        CHUNK_KEY_COLUMN
                                + ": id\n"
                                + CHUNK_KEY_MAP
                                + ": |\n"
                                + "  inventory.dbo.orders: order_id\n"
                                + "  inventory.dbo.users: user_id\n"
                                + "  inventory.audit.orders: audit_id\n");

        assertThat(chunkKey(sourceConfig, "dbo", "orders")).isEqualTo("order_id");
        assertThat(chunkKey(sourceConfig, "dbo", "users")).isEqualTo("user_id");
        assertThat(chunkKey(sourceConfig, "audit", "orders")).isEqualTo("audit_id");
        assertThat(chunkKey(sourceConfig, "dbo", "products")).isEqualTo("id");
    }

    @Test
    void preservesRegexColonsAndColumnPunctuationInYamlMap() throws Exception {
        SqlServerSourceConfig sourceConfig =
                configureYaml(
                        CHUNK_KEY_MAP
                                + ": |\n"
                                + "  'inventory.dbo.(?:orders|users)': 'tenant:id;part]'\n"
                                + "  inventory.audit.orders: ' tenant''s:id;part] '\n"
                                + CHUNK_KEY_COLUMN
                                + ": 'default:id;part'\n");

        assertThat(chunkKey(sourceConfig, "dbo", "orders")).isEqualTo("tenant:id;part]");
        assertThat(chunkKey(sourceConfig, "dbo", "users")).isEqualTo("tenant:id;part]");
        assertThat(chunkKey(sourceConfig, "audit", "orders")).isEqualTo(" tenant's:id;part] ");
        assertThat(chunkKey(sourceConfig, "dbo", "products")).isEqualTo("default:id;part");
    }

    @Test
    void combinesMapAndFlatOptionsForDifferentPatterns() {
        SqlServerSourceConfig sourceConfig =
                configure(
                        Map.of(
                                CHUNK_KEY_MAP,
                                "inventory.dbo.orders: order_id",
                                CHUNK_KEY_BY_TABLE + "inventory.dbo.users",
                                "user_id"));

        assertThat(chunkKey(sourceConfig, "dbo", "orders")).isEqualTo("order_id");
        assertThat(chunkKey(sourceConfig, "dbo", "users")).isEqualTo("user_id");
        assertThat(chunkKey(sourceConfig, "dbo", "products")).isNull();
    }

    @Test
    void acceptsEmptyTableChunkKeyMap() {
        assertThat(chunkKey(configure(Map.of(CHUNK_KEY_MAP, "{}")), "dbo", "orders")).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {"id", "[id]", "null", ""})
    void rejectsNonMapTableChunkKeys(String value) {
        assertThatThrownBy(() -> configure(Map.of(CHUNK_KEY_MAP, value)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(CHUNK_KEY_MAP)
                .hasMessageContaining("must be a map");
    }

    @Test
    void rejectsNonStringMappedColumn() {
        assertThatThrownBy(() -> configure(Map.of(CHUNK_KEY_MAP, "inventory.dbo.orders: [id]")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("inventory.dbo.orders")
                .hasMessageContaining("must be a string");
    }

    @Test
    void rejectsMalformedTableChunkKeyMap() {
        assertThatThrownBy(() -> configure(Map.of(CHUNK_KEY_MAP, "inventory.dbo.orders: [")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid source option")
                .hasMessageContaining(CHUNK_KEY_MAP);
    }

    @Test
    void rejectsDuplicatePatternsInMap() {
        assertThatThrownBy(
                        () ->
                                configure(
                                        Map.of(
                                                CHUNK_KEY_MAP,
                                                "inventory.dbo.orders: id\ninventory.dbo.orders: order_id")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid source option")
                .hasMessageContaining(CHUNK_KEY_MAP);
    }

    @Test
    void rejectsDuplicatePatternsAcrossMapAndFlatOptions() {
        assertThatThrownBy(
                        () ->
                                configure(
                                        Map.of(
                                                CHUNK_KEY_MAP,
                                                "inventory.dbo.orders: id",
                                                CHUNK_KEY_BY_TABLE + "inventory.dbo.orders",
                                                "id")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Duplicate chunk key configuration")
                .hasMessageContaining("inventory.dbo.orders");
    }

    @Test
    void rejectsConflictingMapPatterns() {
        assertThatThrownBy(
                        () ->
                                configure(
                                        Map.of(
                                                CHUNK_KEY_MAP,
                                                "'inventory.dbo.(?:orders|users)': id\n"
                                                        + "inventory.dbo.orders: order_id")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Conflicting chunk key columns")
                .hasMessageContaining("inventory.dbo.orders");
    }

    @Test
    void rejectsBlankColumnInMap() {
        assertThatThrownBy(() -> configure(Map.of(CHUNK_KEY_MAP, "inventory.dbo.orders: ' '")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("non-blank column name");
    }

    @Test
    void rejectsMultipleMapDocuments() {
        assertThatThrownBy(
                        () ->
                                configure(
                                        Map.of(
                                                CHUNK_KEY_MAP,
                                                "inventory.dbo.orders: id\n---\ninventory.dbo.users: user_id")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid source option")
                .hasMessageContaining(CHUNK_KEY_MAP);
    }

    @Test
    void mapsDifferentColumnsToDifferentTables() {
        SqlServerSourceConfig sourceConfig =
                configure(
                        Map.of(
                                CHUNK_KEY_BY_TABLE + "inventory.dbo.orders", "order_id",
                                CHUNK_KEY_BY_TABLE + "inventory.dbo.users", "user_id",
                                CHUNK_KEY_BY_TABLE + "inventory.audit.orders", "audit_id"));

        assertThat(chunkKey(sourceConfig, "dbo", "orders")).isEqualTo("order_id");
        assertThat(chunkKey(sourceConfig, "dbo", "users")).isEqualTo("user_id");
        assertThat(chunkKey(sourceConfig, "audit", "orders")).isEqualTo("audit_id");
        assertThat(chunkKey(sourceConfig, "dbo", "products")).isNull();
        assertThat(sourceConfig.getChunkKeyColumn()).isNull();
    }

    @Test
    void preservesColonsInYamlTablePatternsAndPunctuationInColumnNames() throws Exception {
        SqlServerSourceConfig sourceConfig =
                configureYaml(
                        "'"
                                + CHUNK_KEY_BY_TABLE
                                + "inventory.dbo.(?:orders|users)': 'tenant:id;part'\n"
                                + CHUNK_KEY_COLUMN
                                + ": 'default:id;part'\n");

        assertThat(chunkKey(sourceConfig, "dbo", "orders")).isEqualTo("tenant:id;part");
        assertThat(chunkKey(sourceConfig, "dbo", "users")).isEqualTo("tenant:id;part");
        assertThat(chunkKey(sourceConfig, "audit", "orders")).isEqualTo("default:id;part");
    }

    @Test
    void rejectsConflictingMappingsWhenPatternsOverlap() {
        assertThatThrownBy(
                        () ->
                                configure(
                                        Map.of(
                                                CHUNK_KEY_BY_TABLE
                                                                + "inventory.dbo.(?:orders|users)",
                                                        "id",
                                                CHUNK_KEY_BY_TABLE + "inventory.dbo.orders",
                                                        "order_id")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Conflicting chunk key columns")
                .hasMessageContaining("inventory.dbo.orders");
    }

    @Test
    void ignoresMappingsForExcludedTables() {
        SqlServerSourceConfig sourceConfig =
                configure(
                        Map.of(
                                "tables.exclude",
                                "inventory.dbo.orders",
                                CHUNK_KEY_BY_TABLE + "inventory.dbo.(?:orders|users)",
                                "user_id",
                                CHUNK_KEY_BY_TABLE + "inventory.dbo.orders",
                                "order_id"));

        assertThat(chunkKey(sourceConfig, "dbo", "orders")).isNull();
        assertThat(chunkKey(sourceConfig, "dbo", "users")).isEqualTo("user_id");
    }

    @Test
    void preservesUnconfiguredChunkKey() {
        assertThat(chunkKey(configure(Map.of()), "dbo", "orders")).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "orders", "dbo.orders", "inventory.dbo.orders.extra"})
    void rejectsInvalidTablePatterns(String pattern) {
        assertThatThrownBy(() -> configure(Map.of(CHUNK_KEY_BY_TABLE + pattern, "id")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(CHUNK_KEY_BY_TABLE + pattern)
                .hasMessageContaining("database.schema.table");
    }

    @Test
    void rejectsBlankMappedColumn() {
        assertThatThrownBy(
                        () -> configure(Map.of(CHUNK_KEY_BY_TABLE + "inventory.dbo.orders", " ")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("non-blank column name");
    }

    private static SqlServerSourceConfig configureYaml(String yaml) throws Exception {
        return configure(YAML_MAPPER.readValue(yaml, new TypeReference<Map<String, String>>() {}));
    }

    private static SqlServerSourceConfig configure(Map<String, String> overrides) {
        Map<String, String> options = new HashMap<>();
        options.put("hostname", "localhost");
        options.put("username", "user");
        options.put("password", "password");
        options.put("server-time-zone", "UTC");
        options.put("tables", "inventory.dbo.(orders|users|products),inventory.audit.orders");
        options.putAll(overrides);
        SqlServerDataSourceFactory factory =
                new SqlServerDataSourceFactory() {
                    @Override
                    List<TableId> discoverTables(SqlServerSourceConfig sourceConfig) {
                        return TABLES;
                    }
                };
        Factory.Context context =
                new Factory.Context() {
                    @Override
                    public Configuration getFactoryConfiguration() {
                        return Configuration.fromMap(options);
                    }

                    @Override
                    public Configuration getPipelineConfiguration() {
                        return new Configuration();
                    }

                    @Override
                    public ClassLoader getClassLoader() {
                        return getClass().getClassLoader();
                    }
                };
        return ((SqlServerDataSource) factory.createDataSource(context)).getSqlServerSourceConfig();
    }

    private static String chunkKey(
            SqlServerSourceConfig sourceConfig, String schema, String tableName) {
        return sourceConfig.getChunkKeyColumn(
                new io.debezium.relational.TableId("inventory", schema, tableName));
    }
}
