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

package org.apache.flink.cdc.connectors.sqlserver.source.dialect;

import org.apache.flink.cdc.connectors.base.config.JdbcSourceConfig;
import org.apache.flink.cdc.connectors.base.source.assigner.state.ChunkSplitterState;
import org.apache.flink.cdc.connectors.base.source.meta.split.SnapshotSplit;
import org.apache.flink.cdc.connectors.sqlserver.source.SqlServerSourceBuilder;
import org.apache.flink.cdc.connectors.sqlserver.source.config.SqlServerSourceConfig;
import org.apache.flink.cdc.connectors.sqlserver.source.config.SqlServerSourceConfigFactory;
import org.apache.flink.cdc.connectors.sqlserver.source.reader.fetch.SqlServerSourceFetchTaskContext;
import org.apache.flink.cdc.debezium.JsonDebeziumDeserializationSchema;
import org.apache.flink.table.api.ValidationException;
import org.apache.flink.table.catalog.ObjectPath;
import org.apache.flink.util.InstantiationUtil;

import io.debezium.jdbc.JdbcConnection;
import io.debezium.relational.Column;
import io.debezium.relational.Table;
import io.debezium.relational.TableId;
import io.debezium.relational.history.TableChanges.TableChange;
import io.debezium.relational.history.TableChanges.TableChangeType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.sql.Types;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Tests table-specific chunk keys in both snapshot splitting and reading. */
class SqlServerChunkKeyColumnTest {

    @Test
    void usesEachTablesFirstPrimaryKeyByDefault() throws Exception {
        SqlServerSourceConfig sourceConfig = configFactory().create(0);

        Table orders =
                table("dbo", "orders", "order_id")
                        .edit()
                        .setPrimaryKeyNames("order_id", "id", "fallback_id")
                        .create();
        Table users =
                table("dbo", "users", "user_id")
                        .edit()
                        .setPrimaryKeyNames("user_id", "id", "fallback_id")
                        .create();
        assertChunkKey(sourceConfig, orders, "order_id");
        assertChunkKey(sourceConfig, users, "user_id");
    }

    @Test
    void preservesSourceWideChunkKey() throws Exception {
        SqlServerSourceConfigFactory factory = configFactory();
        factory.chunkKeyColumn("fallback_id");
        SqlServerSourceConfig sourceConfig = factory.create(0);

        assertChunkKey(sourceConfig, table("dbo", "orders", "order_id"), "fallback_id");
        assertChunkKey(sourceConfig, table("dbo", "users", "user_id"), "fallback_id");
    }

    @ParameterizedTest
    @CsvSource({"true, false", "true, true", "false, false", "false, true"})
    void usesNonPrimaryKeyForSplittingAndReading(boolean hasPrimaryKey, boolean tableSpecificKey)
            throws Exception {
        String columnName = "tenant:id;part]";
        SqlServerSourceConfigFactory factory = configFactory();
        if (tableSpecificKey) {
            factory.chunkKeyColumn("id");
            factory.chunkKeyColumns(Map.of(new ObjectPath("dbo", "orders"), columnName));
        } else {
            factory.chunkKeyColumn(columnName);
        }
        Table table =
                table("dbo", "orders", columnName)
                        .edit()
                        .setPrimaryKeyNames(
                                hasPrimaryKey
                                        ? Collections.singletonList("id")
                                        : Collections.emptyList())
                        .create();

        assertChunkKey(factory.create(0), table, columnName);
    }

    @Test
    void requiresExplicitChunkKeyForTablesWithoutPrimaryKeys() {
        SqlServerSourceConfig sourceConfig = configFactory().create(0);
        Table table =
                table("dbo", "orders", "order_id")
                        .edit()
                        .setPrimaryKeyNames(Collections.emptyList())
                        .create();
        SqlServerDialect dialect = new TestingSqlServerDialect(sourceConfig, table);

        assertThatThrownBy(() -> splitter(sourceConfig, dialect).generateSplits(table.id()))
                .hasRootCauseInstanceOf(ValidationException.class)
                .hasStackTraceContaining("chunk.key-column' must be set");
        assertThatThrownBy(() -> fetchContext(sourceConfig, dialect).getSplitType(table))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("chunk.key-column' must be set");
    }

    @Test
    void usesDifferentChunkKeysPerTableAndSchema() throws Exception {
        SqlServerSourceConfigFactory factory = configFactory();
        factory.chunkKeyColumn(new ObjectPath("dbo", "orders"), "order_id");
        factory.chunkKeyColumn(new ObjectPath("dbo", "users"), "user_id");
        factory.chunkKeyColumn(new ObjectPath("audit", "orders"), "fallback_id");
        SqlServerSourceConfig sourceConfig = factory.create(0);

        assertChunkKey(sourceConfig, table("dbo", "orders", "order_id"), "order_id");
        assertChunkKey(sourceConfig, table("dbo", "users", "user_id"), "user_id");
        assertChunkKey(sourceConfig, table("audit", "orders", "order_id"), "fallback_id");
        assertChunkKey(sourceConfig, table("dbo", "products", "product_id"), "id");
    }

    @Test
    void tableSpecificKeyOverridesSourceWideKeyRegardlessOfCallOrder() throws Exception {
        SqlServerSourceConfigFactory factory = configFactory();
        factory.chunkKeyColumn(new ObjectPath("dbo", "orders"), "order_id");
        factory.chunkKeyColumn("fallback_id");
        factory.chunkKeyColumn(new ObjectPath("dbo", "users"), "user_id");
        SqlServerSourceConfig sourceConfig = factory.create(0);

        assertChunkKey(sourceConfig, table("dbo", "orders", "order_id"), "order_id");
        assertChunkKey(sourceConfig, table("dbo", "users", "user_id"), "user_id");
        assertChunkKey(sourceConfig, table("audit", "orders", "order_id"), "fallback_id");
        assertThat(sourceConfig.getChunkKeyColumn()).isEqualTo("fallback_id");
    }

    @Test
    void matchesTablePathsLiterally() throws Exception {
        SqlServerSourceConfigFactory factory = configFactory();
        factory.chunkKeyColumn(new ObjectPath("sales.v1", "orders_2026%"), "order_id");
        SqlServerSourceConfig sourceConfig = factory.create(0);

        assertChunkKey(sourceConfig, table("sales.v1", "orders_2026%", "order_id"), "order_id");
        assertChunkKey(sourceConfig, table("salesXv1", "orders_2026%", "order_id"), "id");
    }

    @Test
    void rejectsMissingTableSpecificColumnInsteadOfFallingBack() {
        SqlServerSourceConfigFactory factory = configFactory();
        factory.chunkKeyColumn("id");
        factory.chunkKeyColumn(new ObjectPath("dbo", "orders"), "missing_id");
        SqlServerSourceConfig sourceConfig = factory.create(0);
        Table table = table("dbo", "orders", "order_id");
        SqlServerDialect dialect = new TestingSqlServerDialect(sourceConfig, table);

        assertThatThrownBy(() -> splitter(sourceConfig, dialect).generateSplits(table.id()))
                .hasRootCauseInstanceOf(ValidationException.class)
                .hasStackTraceContaining("missing_id");
        assertThatThrownBy(() -> fetchContext(sourceConfig, dialect).getSplitType(table))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("missing_id");
    }

    @Test
    void copiesTableConfigurationAndPreservesItDuringSerialization() throws Exception {
        SqlServerSourceConfigFactory factory = configFactory();
        ObjectPath tablePath = new ObjectPath("dbo", "orders");
        factory.chunkKeyColumn(tablePath, "order_id");
        SqlServerSourceConfig firstConfig = factory.create(0);
        factory.chunkKeyColumn(tablePath, "fallback_id");

        SqlServerSourceConfig restoredConfig =
                InstantiationUtil.clone(firstConfig, getClass().getClassLoader());
        Table table = table("dbo", "orders", "order_id");
        assertChunkKey(restoredConfig, table, "order_id");
        assertChunkKey(factory.create(0), table, "fallback_id");
    }

    @Test
    void preservesNullableSourceWideBuilderSetting() {
        SqlServerSourceBuilder<String> builder = new SqlServerSourceBuilder<>();

        assertThat(builder.chunkKeyColumn(null)).isSameAs(builder);
    }

    @Test
    void mergesBulkBuilderSettingsAndKeepsSourceWideFallback() {
        ObjectPath orders = new ObjectPath("dbo", "orders");
        ObjectPath users = new ObjectPath("dbo", "users");
        ObjectPath auditOrders = new ObjectPath("audit", "orders");
        Map<ObjectPath, String> chunkKeys = new HashMap<>();
        chunkKeys.put(orders, "order_id");
        chunkKeys.put(users, "user_id");
        chunkKeys.put(auditOrders, "log_id");

        SqlServerSourceBuilder<String> builder =
                SqlServerSourceBuilder.SqlServerIncrementalSource.<String>builder()
                        .hostname("localhost")
                        .databaseList("inventory")
                        .tableList("dbo.orders", "dbo.users", "audit.orders", "dbo.products")
                        .username("user")
                        .password("password")
                        .deserializer(new JsonDebeziumDeserializationSchema())
                        .chunkKeyColumns(chunkKeys)
                        .chunkKeyColumns(Map.of(auditOrders, "audit_id"))
                        .chunkKeyColumn("id");
        chunkKeys.clear();

        assertThat(builder.build())
                .extracting("configFactory")
                .isInstanceOfSatisfying(
                        SqlServerSourceConfigFactory.class,
                        factory -> {
                            SqlServerSourceConfig config = factory.create(0);
                            assertThat(
                                            config.getChunkKeyColumn(
                                                    new TableId("inventory", "dbo", "orders")))
                                    .isEqualTo("order_id");
                            assertThat(
                                            config.getChunkKeyColumn(
                                                    new TableId("inventory", "dbo", "users")))
                                    .isEqualTo("user_id");
                            assertThat(
                                            config.getChunkKeyColumn(
                                                    new TableId("inventory", "audit", "orders")))
                                    .isEqualTo("audit_id");
                            assertThat(
                                            config.getChunkKeyColumn(
                                                    new TableId("inventory", "dbo", "products")))
                                    .isEqualTo("id");
                        });
    }

    @Test
    void rejectsInvalidBulkSettingsBeforeUpdatingTheFactory() {
        SqlServerSourceConfigFactory factory = configFactory();
        ObjectPath orders = new ObjectPath("dbo", "orders");
        ObjectPath users = new ObjectPath("dbo", "users");
        factory.chunkKeyColumns(Map.of(orders, "fallback_id"));

        Map<ObjectPath, String> invalidChunkKeys = new LinkedHashMap<>();
        invalidChunkKeys.put(orders, "order_id");
        invalidChunkKeys.put(users, null);

        assertThatThrownBy(() -> factory.chunkKeyColumns(invalidChunkKeys))
                .isInstanceOf(NullPointerException.class);
        SqlServerSourceConfig config = factory.create(0);
        assertThat(config.getChunkKeyColumn(new TableId("inventory", "dbo", "orders")))
                .isEqualTo("fallback_id");
        assertThat(config.getChunkKeyColumn(new TableId("inventory", "dbo", "users"))).isNull();
    }

    private static void assertChunkKey(
            SqlServerSourceConfig sourceConfig, Table table, String columnName) throws Exception {
        SqlServerDialect dialect = new TestingSqlServerDialect(sourceConfig, table);
        Collection<SnapshotSplit> splits =
                splitter(sourceConfig, dialect).generateSplits(table.id());

        assertThat(splits).hasSize(1);
        assertThat(splits.iterator().next().getSplitKeyType().getFieldNames())
                .containsExactly(columnName);
        assertThat(fetchContext(sourceConfig, dialect).getSplitType(table).getFieldNames())
                .containsExactly(columnName);
    }

    private static SqlServerSourceFetchTaskContext fetchContext(
            SqlServerSourceConfig sourceConfig, SqlServerDialect dialect) {
        return new SqlServerSourceFetchTaskContext(sourceConfig, dialect, null, null);
    }

    private static SqlServerChunkSplitter splitter(
            SqlServerSourceConfig sourceConfig, SqlServerDialect dialect) {
        return new SqlServerChunkSplitter(
                sourceConfig, dialect, ChunkSplitterState.NO_SPLITTING_TABLE_STATE) {
            @Override
            protected Object[] queryMinMax(
                    JdbcConnection jdbc, TableId tableId, Column splitColumn) {
                return new Object[] {1, 10};
            }

            @Override
            protected Long queryApproximateRowCnt(JdbcConnection jdbc, TableId tableId) {
                return 10L;
            }
        };
    }

    private static SqlServerSourceConfigFactory configFactory() {
        SqlServerSourceConfigFactory factory = new SqlServerSourceConfigFactory();
        factory.hostname("localhost")
                .port(1433)
                .databaseList("inventory")
                .tableList("dbo.orders", "dbo.users", "audit.orders", "dbo.products")
                .username("user")
                .password("password")
                .serverTimeZone("UTC");
        return factory;
    }

    private static Table table(String schema, String tableName, String chunkKey) {
        return Table.editor()
                .tableId(new TableId("inventory", schema, tableName))
                .addColumns(column("id"), column("fallback_id"), column(chunkKey))
                .setPrimaryKeyNames("id", "fallback_id", chunkKey)
                .create();
    }

    private static Column column(String name) {
        return Column.editor().name(name).jdbcType(Types.INTEGER).type("int").create();
    }

    private static class TestingSqlServerDialect extends SqlServerDialect {
        private final Table table;

        TestingSqlServerDialect(SqlServerSourceConfig sourceConfig, Table table) {
            super(sourceConfig);
            this.table = table;
        }

        @Override
        public JdbcConnection openJdbcConnection(JdbcSourceConfig sourceConfig) {
            return null;
        }

        @Override
        public TableChange queryTableSchema(JdbcConnection jdbc, TableId tableId) {
            return new TableChange(TableChangeType.CREATE, table);
        }
    }
}
