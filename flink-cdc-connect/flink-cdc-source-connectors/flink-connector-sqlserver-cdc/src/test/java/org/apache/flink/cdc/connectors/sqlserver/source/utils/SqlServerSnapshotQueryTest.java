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

import io.debezium.relational.TableId;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

/** Tests for quoting snapshot split keys in SQL Server queries. */
class SqlServerSnapshotQueryTest {

    @ParameterizedTest
    @CsvSource(
            value = {"tenant:id|[tenant:id]", "tenant;id]|[tenant;id]]]"},
            delimiter = '|')
    void quotesTheColumnInEachSnapshotRange(String columnName, String quotedColumn) {
        TableId tableId = new TableId("customer", "dbo", "orders");
        RowType splitKeyType =
                (RowType)
                        DataTypes.ROW(DataTypes.FIELD(columnName, DataTypes.INT()))
                                .getLogicalType();
        String select = "SELECT * FROM [dbo].[orders]";

        assertThat(SqlServerUtils.buildSplitScanQuery(tableId, splitKeyType, true, true))
                .isEqualTo(select);
        assertThat(SqlServerUtils.buildSplitScanQuery(tableId, splitKeyType, true, false))
                .isEqualTo(
                        select
                                + " WHERE "
                                + quotedColumn
                                + " <= ? AND NOT ("
                                + quotedColumn
                                + " = ?)");
        assertThat(SqlServerUtils.buildSplitScanQuery(tableId, splitKeyType, false, false))
                .isEqualTo(
                        select
                                + " WHERE "
                                + quotedColumn
                                + " >= ? AND NOT ("
                                + quotedColumn
                                + " = ?) AND "
                                + quotedColumn
                                + " <= ?");
        assertThat(SqlServerUtils.buildSplitScanQuery(tableId, splitKeyType, false, true))
                .isEqualTo(select + " WHERE " + quotedColumn + " >= ?");
    }
}
