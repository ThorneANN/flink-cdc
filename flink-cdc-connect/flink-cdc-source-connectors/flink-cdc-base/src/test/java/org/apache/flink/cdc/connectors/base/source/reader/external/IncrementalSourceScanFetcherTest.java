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

package org.apache.flink.cdc.connectors.base.source.reader.external;

import org.apache.flink.cdc.connectors.base.config.JdbcSourceConfig;
import org.apache.flink.cdc.connectors.base.source.meta.offset.Offset;
import org.apache.flink.cdc.connectors.base.source.meta.split.SnapshotSplit;
import org.apache.flink.cdc.connectors.base.source.meta.split.SourceRecords;
import org.apache.flink.cdc.connectors.base.source.meta.split.SourceSplitBase;
import org.apache.flink.cdc.connectors.base.source.meta.wartermark.WatermarkEvent;
import org.apache.flink.cdc.connectors.base.source.meta.wartermark.WatermarkKind;
import org.apache.flink.table.api.DataTypes;
import org.apache.flink.table.types.logical.RowType;

import io.debezium.connector.base.ChangeEventQueue;
import io.debezium.data.Envelope;
import io.debezium.pipeline.DataChangeEvent;
import io.debezium.relational.TableId;
import io.debezium.util.LoggingContext;
import org.apache.kafka.connect.data.Schema;
import org.apache.kafka.connect.data.SchemaBuilder;
import org.apache.kafka.connect.data.Struct;
import org.apache.kafka.connect.source.SourceRecord;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Tests snapshot buffering with and without message keys. */
class IncrementalSourceScanFetcherTest {
    private static final Schema ROW_SCHEMA =
            SchemaBuilder.struct()
                    .name("inventory.dbo.rows.Value")
                    .optional()
                    .field("id", Schema.OPTIONAL_STRING_SCHEMA)
                    .field("chunk", Schema.STRING_SCHEMA)
                    .build();
    private static final Schema SOURCE_SCHEMA =
            SchemaBuilder.struct().name("source").field("ts_ms", Schema.INT64_SCHEMA).build();
    private static final Schema VALUE_SCHEMA =
            SchemaBuilder.struct()
                    .field("before", ROW_SCHEMA)
                    .field("after", ROW_SCHEMA)
                    .field("source", SOURCE_SCHEMA)
                    .field("op", Schema.STRING_SCHEMA)
                    .field("ts_ms", Schema.INT64_SCHEMA)
                    .build();
    private static final Schema KEY_SCHEMA =
            SchemaBuilder.struct().field("id", Schema.STRING_SCHEMA).build();

    @Test
    void preservesRowsWithRepeatedChunkKeysAndIdenticalDuplicates() throws Exception {
        List<SourceRecord> snapshot =
                Arrays.asList(
                        read("first", "a"),
                        read("second", "a"),
                        read("first", "a"),
                        read(null, "b"));
        assertThat(readSplit(snapshot, Collections.emptyList(), null, null))
                .containsExactlyInAnyOrder("first:a", "second:a", "first:a", "null:b");
    }

    @Test
    void deletesOnlyOneCopyAndMatchesRowsWithoutEnvelopeMetadata() throws Exception {
        List<SourceRecord> snapshot =
                Arrays.asList(read("first", "a"), read("first", "a"), read("second", "a"));
        SourceRecord deletion = change("d", row("first", "a"), null, false, 99L);
        assertThat(readSplit(snapshot, Collections.singletonList(deletion), null, null))
                .containsExactlyInAnyOrder("first:a", "second:a");
    }

    @Test
    void updatesOnlyOneCopyAndPreservesExistingCopiesOfTheNewRow() throws Exception {
        List<SourceRecord> snapshot =
                Arrays.asList(read("old", "a"), read("old", "a"), read("new", "a"));
        SourceRecord update = change("u", row("old", "a"), row("new", "a"), false, 99L);
        assertThat(readSplit(snapshot, Collections.singletonList(update), null, null))
                .containsExactlyInAnyOrder("old:a", "new:a", "new:a");
    }

    @Test
    void appendsRepeatedInsertsAndIgnoresTombstones() throws Exception {
        SourceRecord insertion = change("c", null, row("first", "a"), false, 99L);
        SourceRecord tombstone =
                new SourceRecord(
                        Collections.emptyMap(), Collections.emptyMap(), "rows", null, null);
        assertThat(
                        readSplit(
                                Collections.singletonList(read("first", "a")),
                                Arrays.asList(insertion, insertion, tombstone),
                                null,
                                null))
                .containsExactlyInAnyOrder("first:a", "first:a", "first:a");
    }

    @Test
    void ignoresBackfillOutsideTheSplit() throws Exception {
        SourceRecord insertion = change("c", null, row("outside", "z"), false, 99L);
        assertThat(
                        readSplit(
                                Collections.singletonList(read("inside", "b")),
                                Collections.singletonList(insertion),
                                new Object[] {"a"},
                                new Object[] {"c"}))
                .containsExactly("inside:b");
    }

    @Test
    void movesKeylessUpdatesAcrossChunkBoundaries() throws Exception {
        SourceRecord incoming = change("u", row("incoming", "z"), row("incoming", "b"), false, 99L);
        SourceRecord outgoing =
                change("u", row("outgoing", "b"), row("outgoing", "z"), false, 100L);
        assertThat(
                        readSplit(
                                Collections.singletonList(read("outgoing", "b")),
                                Arrays.asList(incoming, outgoing),
                                new Object[] {"a"},
                                new Object[] {"c"}))
                .containsExactly("incoming:b");
    }

    @Test
    void keepsKeyedSnapshotAndBackfillBehavior() throws Exception {
        List<SourceRecord> snapshot =
                Arrays.asList(
                        change("r", null, row("first", "a"), true, 1L),
                        change("r", null, row("second", "b"), true, 1L));
        List<SourceRecord> changes =
                Arrays.asList(
                        change("u", row("first", "a"), row("first", "c"), true, 99L),
                        change("d", row("second", "b"), null, true, 100L),
                        change("c", null, row("third", "d"), true, 101L));
        assertThat(readSplit(snapshot, changes, null, null))
                .containsExactlyInAnyOrder("first:c", "third:d");
    }

    @Test
    void ignoresDeletesForRowsAbsentFromTheSnapshot() throws Exception {
        SourceRecord deletion = change("d", row("absent", "a"), null, false, 99L);
        assertThat(
                        readSplit(
                                Collections.singletonList(read("first", "a")),
                                Collections.singletonList(deletion),
                                null,
                                null))
                .containsExactly("first:a");
    }

    private List<String> readSplit(
            List<SourceRecord> snapshot, List<SourceRecord> changes, Object[] start, Object[] end)
            throws Exception {
        ChangeEventQueue<DataChangeEvent> queue =
                new ChangeEventQueue.Builder<DataChangeEvent>()
                        .pollInterval(Duration.ofMillis(10))
                        .loggingContextSupplier(
                                () -> LoggingContext.forConnector("test", "test", "test"))
                        .maxBatchSize(100)
                        .maxQueueSize(1000)
                        .build();
        JdbcSourceFetchTaskContext context =
                mock(JdbcSourceFetchTaskContext.class, CALLS_REAL_METHODS);
        doReturn(queue).when(context).getQueue();
        doReturn(mock(JdbcSourceConfig.class)).when(context).getSourceConfig();
        doNothing().when(context).configure(any());
        doAnswer(
                        invocation -> {
                            SourceRecord record = invocation.getArgument(0);
                            Struct value = (Struct) record.value();
                            Envelope.Operation operation = Envelope.operationFor(record);
                            Struct data =
                                    value.getStruct(
                                            operation == Envelope.Operation.READ
                                                            || operation
                                                                    == Envelope.Operation.CREATE
                                                    ? "after"
                                                    : "before");
                            return new Object[] {data.getString("chunk")};
                        })
                .when(context)
                .getSplitKey(any());
        SnapshotSplit split =
                new SnapshotSplit(
                        new TableId("inventory", "dbo", "rows"),
                        0,
                        (RowType)
                                DataTypes.ROW(DataTypes.FIELD("chunk", DataTypes.STRING()))
                                        .getLogicalType(),
                        start,
                        end,
                        null,
                        Collections.emptyMap());
        Offset watermark = mock(Offset.class);
        when(watermark.getOffset()).thenReturn(Collections.emptyMap());
        queue.enqueue(
                new DataChangeEvent(
                        WatermarkEvent.create(
                                Collections.emptyMap(),
                                "rows",
                                split.splitId(),
                                WatermarkKind.LOW,
                                watermark)));
        for (SourceRecord record : snapshot) {
            queue.enqueue(new DataChangeEvent(record));
        }
        queue.enqueue(
                new DataChangeEvent(
                        WatermarkEvent.create(
                                Collections.emptyMap(),
                                "rows",
                                split.splitId(),
                                WatermarkKind.HIGH,
                                watermark)));
        for (SourceRecord record : changes) {
            queue.enqueue(new DataChangeEvent(record));
        }
        queue.enqueue(
                new DataChangeEvent(
                        WatermarkEvent.create(
                                Collections.emptyMap(),
                                "rows",
                                split.splitId(),
                                WatermarkKind.END,
                                watermark)));
        FetchTask<SourceSplitBase> task = mock(FetchTask.class);
        when(task.getSplit()).thenReturn(split);
        IncrementalSourceScanFetcher fetcher = new IncrementalSourceScanFetcher(context, 0);
        try {
            fetcher.submitTask(task);
            Iterator<SourceRecords> batches = fetcher.pollSplitRecords();
            List<String> rows = new ArrayList<>();
            while (batches.hasNext()) {
                for (SourceRecord record : batches.next().getSourceRecordList()) {
                    if (context.isDataChangeRecord(record)) {
                        Struct data = ((Struct) record.value()).getStruct("after");
                        rows.add(data.getString("id") + ":" + data.getString("chunk"));
                    }
                }
            }
            return rows;
        } finally {
            fetcher.close();
        }
    }

    private static Struct row(String id, String chunk) {
        return new Struct(ROW_SCHEMA).put("id", id).put("chunk", chunk);
    }

    private static SourceRecord read(String id, String chunk) {
        return change("r", null, row(id, chunk), false, 1L);
    }

    private static SourceRecord change(
            String operation, Struct before, Struct after, boolean keyed, long timestamp) {
        Struct value =
                new Struct(VALUE_SCHEMA)
                        .put("before", before)
                        .put("after", after)
                        .put("source", new Struct(SOURCE_SCHEMA).put("ts_ms", timestamp))
                        .put("op", operation)
                        .put("ts_ms", timestamp);
        Struct key =
                keyed
                        ? new Struct(KEY_SCHEMA)
                                .put("id", (after == null ? before : after).getString("id"))
                        : null;
        return new SourceRecord(
                Collections.emptyMap(),
                Map.of("pos", timestamp),
                "inventory.dbo.rows",
                keyed ? KEY_SCHEMA : null,
                key,
                VALUE_SCHEMA,
                value);
    }
}
