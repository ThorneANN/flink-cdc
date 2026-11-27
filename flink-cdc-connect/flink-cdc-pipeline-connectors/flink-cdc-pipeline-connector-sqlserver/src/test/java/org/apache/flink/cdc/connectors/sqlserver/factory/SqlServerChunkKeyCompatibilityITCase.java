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
import org.apache.flink.cdc.common.factories.Factory;
import org.apache.flink.cdc.connectors.sqlserver.SqlServerTestBase;
import org.apache.flink.cdc.connectors.sqlserver.source.SqlServerDataSource;
import org.apache.flink.cdc.connectors.sqlserver.source.config.SqlServerSourceConfig;
import org.apache.flink.cdc.connectors.sqlserver.utils.SqlServerSchemaUtils;

import io.debezium.relational.TableId;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.testcontainers.containers.MSSQLServerContainer.MS_SQL_SERVER_PORT;

/** Tests ambiguous chunk-key values against physical SQL Server column names. */
class SqlServerChunkKeyCompatibilityITCase extends SqlServerTestBase {

    private static final String DATABASE = "chunk_key_compat";
    private static final String OPTION = "scan.incremental.snapshot.chunk.key-column";
    private static final String[] LITERAL_COLUMNS = {
        "chunk_key_compat.dbo.orders:id",
        "chunk_key_compat.dbo.orders:tenant;id",
        "chunk_key_compat.dbo.orders:id;chunk_key_compat.dbo.users:user_id"
    };

    @BeforeAll
    static void createTables() throws Exception {
        try (Connection connection =
                        DriverManager.getConnection(
                                MSSQL_SERVER_CONTAINER.getJdbcUrl(),
                                MSSQL_SERVER_CONTAINER.getUsername(),
                                MSSQL_SERVER_CONTAINER.getPassword());
                Statement statement = connection.createStatement()) {
            statement.execute("CREATE DATABASE " + SqlServerSchemaUtils.quote(DATABASE));
            statement.execute("USE " + SqlServerSchemaUtils.quote(DATABASE));
            for (String table : Arrays.asList("orders", "users")) {
                StringBuilder ddl =
                        new StringBuilder("CREATE TABLE dbo.")
                                .append(table)
                                .append(" (id INT PRIMARY KEY, ")
                                .append("order_id INT NOT NULL, user_id INT NOT NULL, ")
                                .append("[tenant:id;part]]] INT NOT NULL");
                for (String column : LITERAL_COLUMNS) {
                    ddl.append(", ")
                            .append(SqlServerSchemaUtils.quote(column))
                            .append(" INT NOT NULL");
                }
                statement.execute(ddl.append(")").toString());
            }
            statement.execute(
                    "CREATE TABLE dbo.excluded ("
                            + SqlServerSchemaUtils.quote(DATABASE + ".dbo.orders:order_id")
                            + " INT NOT NULL)");
        }
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "chunk_key_compat.dbo.orders:id",
                "chunk_key_compat.dbo.orders:tenant;id",
                "chunk_key_compat.dbo.orders:id;chunk_key_compat.dbo.users:user_id"
            })
    void preservesExistingLiteralColumn(String columnName) {
        SqlServerSourceConfig config = configure(columnName, Map.of());

        assertThat(config.getChunkKeyColumn()).isEqualTo(columnName);
        assertThat(config.getChunkKeyColumn(new TableId(DATABASE, "dbo", "orders")))
                .isEqualTo(columnName);
        assertThat(config.getChunkKeyColumn(new TableId(DATABASE, "dbo", "users")))
                .isEqualTo(columnName);
    }

    @Test
    void parsesMappingsWhenNoPhysicalColumnHasTheEntireValue() {
        SqlServerSourceConfig config =
                configure(
                        DATABASE
                                + ".dbo.(?x)orders # comment:ignored\n:tenant:id\\;part];"
                                + DATABASE
                                + ".dbo.users:user_id",
                        Map.of());

        assertThat(config.getChunkKeyColumn()).isNull();
        assertThat(config.getChunkKeyColumn(new TableId(DATABASE, "dbo", "orders")))
                .isEqualTo("tenant:id;part]");
        assertThat(config.getChunkKeyColumn(new TableId(DATABASE, "dbo", "users")))
                .isEqualTo("user_id");
    }

    @Test
    void ignoresLiteralColumnsInExcludedTables() {
        SqlServerSourceConfig config =
                configure(
                        DATABASE + ".dbo.orders:order_id",
                        Map.of(
                                "tables", DATABASE + ".dbo.(orders|users|excluded)",
                                "tables.exclude", DATABASE + ".dbo.excluded"));

        assertThat(config.getChunkKeyColumn()).isNull();
        assertThat(config.getChunkKeyColumn(new TableId(DATABASE, "dbo", "orders")))
                .isEqualTo("order_id");
        assertThat(config.getChunkKeyColumn(new TableId(DATABASE, "dbo", "users"))).isNull();
    }

    private SqlServerSourceConfig configure(String value, Map<String, String> overrides) {
        Map<String, String> options = new HashMap<>();
        options.put("hostname", MSSQL_SERVER_CONTAINER.getHost());
        options.put(
                "port", String.valueOf(MSSQL_SERVER_CONTAINER.getMappedPort(MS_SQL_SERVER_PORT)));
        options.put("username", MSSQL_SERVER_CONTAINER.getUsername());
        options.put("password", MSSQL_SERVER_CONTAINER.getPassword());
        options.put("server-time-zone", "UTC");
        options.put("tables", DATABASE + ".dbo.(orders|users)");
        options.put(OPTION, value);
        options.putAll(overrides);
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
        return ((SqlServerDataSource) new SqlServerDataSourceFactory().createDataSource(context))
                .getSqlServerSourceConfig();
    }
}
