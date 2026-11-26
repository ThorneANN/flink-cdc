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

package org.apache.flink.cdc.connectors.sqlserver.source.reader.fetch;

import org.apache.flink.cdc.connectors.base.source.assigner.state.ChunkSplitterState;
import org.apache.flink.cdc.connectors.base.source.meta.split.SnapshotSplit;
import org.apache.flink.cdc.connectors.base.source.meta.split.SourceRecords;
import org.apache.flink.cdc.connectors.base.source.meta.split.SourceSplitBase;
import org.apache.flink.cdc.connectors.base.source.reader.external.AbstractScanFetchTask;
import org.apache.flink.cdc.connectors.base.source.reader.external.FetchTask;
import org.apache.flink.cdc.connectors.base.source.reader.external.IncrementalSourceScanFetcher;
import org.apache.flink.cdc.connectors.base.source.utils.hooks.SnapshotPhaseHooks;
import org.apache.flink.cdc.connectors.base.utils.SourceRecordUtils;
import org.apache.flink.cdc.connectors.sqlserver.source.SqlServerSourceTestBase;
import org.apache.flink.cdc.connectors.sqlserver.source.config.SqlServerSourceConfig;
import org.apache.flink.cdc.connectors.sqlserver.source.config.SqlServerSourceConfigFactory;
import org.apache.flink.cdc.connectors.sqlserver.source.dialect.SqlServerChunkSplitter;
import org.apache.flink.cdc.connectors.sqlserver.source.dialect.SqlServerDialect;

import io.debezium.relational.TableId;
import org.apache.kafka.connect.data.Struct;
import org.apache.kafka.connect.source.SourceRecord;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import static org.apache.flink.cdc.connectors.sqlserver.SqlServerTestBase.getConfigFactory;
import static org.apache.flink.cdc.connectors.sqlserver.source.utils.SqlServerConnectionUtils.createSqlServerConnection;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/** Tests keyless SQL Server snapshots and changelog reconciliation. */
@Timeout(120)
class SqlServerKeylessSnapshotITCase extends SqlServerSourceTestBase {
    private static final String TABLE = "sys_notify_todotarget";
    private static final String[][] SAMPLE_ROWS = {
        {"1a1b1d6a317c4b8751813f64d04bdcef", "176b82fb49204a703c92ce244f4b7ead"},
        {"1a147e5fdf15e1eb3a643224c4ea358f", "69dbc6d3efdc6ae3359beb5c4f880730"},
        {"1a1b3f97c0c52a4e6e54f3f4a8c847cb", "176b82e2e16895088061a144d1ca087b"},
        {"1a0ebb0846b571bf0fa34024e30a647d", "1ddce300759c50a80661f6f10424bfd5"},
        {"1a1c2eb90b30ca0073360924effaa71f", "176b82e2e16895088061a144d1ca087b"},
        {"1a15bcc51d83b3bfa6068144732bab93", "eaf8f79b4faf0bb00054839140efeb64"},
        {"1a21694325352de27f62b6b4890ac8ad", "c60139d7af2c4db6fdd107d2e3ca15b6"},
        {"1a1ae32a43c185f5dafd10a4897a03a8", "eaf8f79b4faf0bb00054839140efeb64"},
        {"1a15c2f8019107c12c0f40f4ff4a0208", "d096e6bbec94a63101695d68011b63f3"},
        {"1a12f5720dfaf58e0f852914214ba4e4", "176b82fbdd670d24a5b4df84404b5947"}
    };

    @ParameterizedTest
    @ValueSource(ints = {3, 8096})
    void preservesKeylessRowsAndIdenticalDuplicates(int chunkSize) throws Exception {
        String database = "keyless_snapshot_" + chunkSize;
        createTable(database);
        List<String> expected = new ArrayList<>();
        for (String[] row : SAMPLE_ROWS) {
            insert(database, row[0], row[1]);
            expected.add(Arrays.toString(row));
        }
        insert(database, SAMPLE_ROWS[0][0], SAMPLE_ROWS[0][1]);
        expected.add(Arrays.toString(SAMPLE_ROWS[0]));
        waitForCapturedInserts(database, expected.size());

        assertThat(readSnapshot(database, chunkSize, SnapshotPhaseHooks.empty()))
                .containsExactlyInAnyOrderElementsOf(expected);
    }

    @Test
    void reconcilesInsertUpdateAndSingleCopyDeleteDuringSnapshot() throws Exception {
        String database = "keyless_backfill";
        createTable(database);
        insert(database, "duplicate", "a");
        insert(database, "duplicate", "a");
        insert(database, "old", "b");
        waitForCapturedInserts(database, 3);
        SnapshotPhaseHooks hooks = new SnapshotPhaseHooks();
        hooks.setPreHighWatermarkAction(
                (config, split) -> {
                    executeSql(
                            "USE "
                                    + database
                                    + "; DELETE TOP (1) FROM dbo."
                                    + TABLE
                                    + " WHERE fd_todoid = N'duplicate';"
                                    + " UPDATE dbo."
                                    + TABLE
                                    + " SET fd_todoid = N'new' WHERE fd_todoid = N'old';"
                                    + " INSERT INTO dbo."
                                    + TABLE
                                    + " VALUES (NULL, N'c');");
                    await().atMost(Duration.ofSeconds(30))
                            .until(
                                    () -> {
                                        try (Connection connection = getJdbcConnection();
                                                Statement statement = connection.createStatement();
                                                ResultSet result =
                                                        statement.executeQuery(
                                                                "SELECT COUNT(*) FROM "
                                                                        + database
                                                                        + ".cdc.dbo_"
                                                                        + TABLE
                                                                        + "_CT WHERE fd_todoid IS NULL AND __$operation = 2")) {
                                            result.next();
                                            return result.getInt(1) > 0;
                                        }
                                    });
                });

        assertThat(readSnapshot(database, 8096, hooks))
                .containsExactlyInAnyOrder("[duplicate, a]", "[new, b]", "[null, c]");
    }

    private void waitForCapturedInserts(String database, int expected) {
        await().atMost(Duration.ofSeconds(30))
                .until(
                        () -> {
                            try (Connection connection = getJdbcConnection();
                                    Statement statement = connection.createStatement();
                                    ResultSet result =
                                            statement.executeQuery(
                                                    "SELECT COUNT(*) FROM "
                                                            + database
                                                            + ".cdc.dbo_"
                                                            + TABLE
                                                            + "_CT WHERE __$operation = 2")) {
                                result.next();
                                return result.getInt(1) == expected;
                            }
                        });
    }

    private void createTable(String database) {
        executeSql("CREATE DATABASE " + database);
        executeSql(
                "USE "
                        + database
                        + "; EXEC sys.sp_cdc_enable_db;"
                        + " CREATE TABLE dbo."
                        + TABLE
                        + " (fd_todoid NVARCHAR(255), fd_orgid NVARCHAR(36) NOT NULL);"
                        + " EXEC sys.sp_cdc_enable_table @source_schema = N'dbo', @source_name = N'"
                        + TABLE
                        + "', @role_name = NULL, @supports_net_changes = 0;");
    }

    private void insert(String database, String todo, String org) {
        executeSql(
                "INSERT INTO "
                        + database
                        + ".dbo."
                        + TABLE
                        + " VALUES (N'"
                        + todo
                        + "', N'"
                        + org
                        + "')");
    }

    private List<String> readSnapshot(String database, int chunkSize, SnapshotPhaseHooks hooks)
            throws Exception {
        SqlServerSourceConfigFactory factory =
                getConfigFactory(database, new String[] {"dbo." + TABLE}, chunkSize);
        factory.chunkKeyColumns("dbo." + TABLE + ":fd_orgid");
        SqlServerSourceConfig config = factory.create(0);
        SqlServerDialect dialect = new SqlServerDialect(config);
        SqlServerChunkSplitter splitter =
                new SqlServerChunkSplitter(
                        config, dialect, ChunkSplitterState.NO_SPLITTING_TABLE_STATE);
        List<SnapshotSplit> splits = new ArrayList<>();
        try {
            splitter.open();
            do {
                splits.addAll(splitter.generateSplits(new TableId(database, "dbo", TABLE)));
            } while (splitter.hasNextChunk());
        } finally {
            splitter.close();
        }
        SqlServerSourceFetchTaskContext context =
                new SqlServerSourceFetchTaskContext(
                        config,
                        dialect,
                        createSqlServerConnection(config.getDbzConnectorConfig()),
                        createSqlServerConnection(config.getDbzConnectorConfig()));
        IncrementalSourceScanFetcher fetcher = new IncrementalSourceScanFetcher(context, 0);
        List<String> result = new ArrayList<>();
        try {
            for (SnapshotSplit split : splits) {
                FetchTask<SourceSplitBase> task = dialect.createFetchTask(split);
                ((AbstractScanFetchTask) task).setSnapshotPhaseHooks(hooks);
                fetcher.submitTask(task);
                Iterator<SourceRecords> batches;
                while ((batches = fetcher.pollSplitRecords()) != null) {
                    while (batches.hasNext()) {
                        for (SourceRecord record : batches.next().getSourceRecordList()) {
                            if (SourceRecordUtils.isDataChangeRecord(record)) {
                                assertThat(record.key()).isNull();
                                Struct row = ((Struct) record.value()).getStruct("after");
                                result.add(
                                        Arrays.toString(
                                                new Object[] {
                                                    row.get("fd_todoid"), row.get("fd_orgid")
                                                }));
                            }
                        }
                    }
                }
                await().atMost(Duration.ofSeconds(30)).until(fetcher::isFinished);
            }
        } finally {
            fetcher.close();
        }
        return result;
    }
}
