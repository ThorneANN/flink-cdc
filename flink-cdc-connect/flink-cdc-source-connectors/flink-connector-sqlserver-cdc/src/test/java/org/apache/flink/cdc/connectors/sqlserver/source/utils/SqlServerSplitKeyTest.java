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

import org.apache.flink.table.api.DataTypes;
import org.apache.flink.table.types.logical.RowType;

import io.debezium.data.Envelope;
import io.debezium.util.SchemaNameAdjuster;
import org.apache.kafka.connect.data.Schema;
import org.apache.kafka.connect.data.SchemaBuilder;
import org.apache.kafka.connect.data.Struct;
import org.apache.kafka.connect.source.SourceRecord;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

/** Tests chunk key extraction from SQL Server data change events. */
class SqlServerSplitKeyTest {

    private static final String COLUMN_NAME = "tenant:id;part]";
    private static final SchemaNameAdjuster NAME_ADJUSTER = SchemaNameAdjuster.create();
    private static final String FIELD_NAME = NAME_ADJUSTER.adjust(COLUMN_NAME);

    @ParameterizedTest
    @CsvSource({
        "r, true, 30",
        "c, true, 30",
        "u, true, 20",
        "d, true, 20",
        "r, false, 30",
        "c, false, 30",
        "u, false, 20",
        "d, false, 20"
    })
    void extractsNonPrimaryKeyFromRowData(String operation, boolean hasKey, int expectedValue) {
        assertThat(
                        SqlServerUtils.getSplitKey(
                                splitType(COLUMN_NAME), record(operation, hasKey), NAME_ADJUSTER))
                .containsExactly(expectedValue);
    }

    @ParameterizedTest
    @ValueSource(strings = {"r", "c", "u", "d"})
    void preservesPrimaryKeyExtraction(String operation) {
        assertThat(
                        SqlServerUtils.getSplitKey(
                                splitType("id"), record(operation, true), NAME_ADJUSTER))
                .containsExactly(1);
    }

    private static RowType splitType(String columnName) {
        return (RowType)
                DataTypes.ROW(DataTypes.FIELD(columnName, DataTypes.INT())).getLogicalType();
    }

    private static SourceRecord record(String operation, boolean hasKey) {
        Schema rowSchema =
                SchemaBuilder.struct()
                        .field("id", Schema.INT32_SCHEMA)
                        .field(FIELD_NAME, Schema.INT32_SCHEMA)
                        .optional()
                        .build();
        Schema valueSchema =
                SchemaBuilder.struct()
                        .field(Envelope.FieldName.BEFORE, rowSchema)
                        .field(Envelope.FieldName.AFTER, rowSchema)
                        .field(Envelope.FieldName.OPERATION, Schema.STRING_SCHEMA)
                        .build();
        Struct before =
                "u".equals(operation) || "d".equals(operation)
                        ? new Struct(rowSchema).put("id", 1).put(FIELD_NAME, 20)
                        : null;
        Struct after =
                "d".equals(operation)
                        ? null
                        : new Struct(rowSchema).put("id", 1).put(FIELD_NAME, 30);
        Struct value =
                new Struct(valueSchema)
                        .put(Envelope.FieldName.BEFORE, before)
                        .put(Envelope.FieldName.AFTER, after)
                        .put(Envelope.FieldName.OPERATION, operation);
        Schema keySchema = SchemaBuilder.struct().field("id", Schema.INT32_SCHEMA).build();
        return new SourceRecord(
                Collections.emptyMap(),
                Collections.emptyMap(),
                "inventory.dbo.orders",
                hasKey ? keySchema : null,
                hasKey ? new Struct(keySchema).put("id", 1) : null,
                valueSchema,
                value);
    }
}
