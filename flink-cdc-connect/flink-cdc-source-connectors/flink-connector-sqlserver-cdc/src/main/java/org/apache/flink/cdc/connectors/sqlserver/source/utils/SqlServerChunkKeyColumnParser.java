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

import org.apache.flink.cdc.common.annotation.Internal;
import org.apache.flink.table.catalog.ObjectPath;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;

import static org.apache.flink.util.Preconditions.checkArgument;
import static org.apache.flink.util.Preconditions.checkNotNull;

/** Parses table-to-column mappings shared by the DataStream and Pipeline sources. */
@Internal
public final class SqlServerChunkKeyColumnParser {

    private SqlServerChunkKeyColumnParser() {}

    public static Map<String, String> parse(String value) {
        checkNotNull(value, "Table chunk keys must not be null.");
        Map<String, String> columns = new HashMap<>();
        StringBuilder table = new StringBuilder();
        StringBuilder column = new StringBuilder();
        boolean readingColumn = false;
        int groupDepth = 0;
        Deque<Integer> characterClasses = new ArrayDeque<>();
        boolean quotedPattern = false;
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            StringBuilder target = readingColumn ? column : table;
            if (current == '\\') {
                checkArgument(index + 1 < value.length(), "Unterminated chunk key escape.");
                char escaped = value.charAt(++index);
                if (!readingColumn || ";:\\".indexOf(escaped) < 0) {
                    target.append('\\');
                }
                target.append(escaped);
                if (!readingColumn && escaped == 'Q' && !quotedPattern) {
                    quotedPattern = true;
                } else if (!readingColumn && escaped == 'E' && quotedPattern) {
                    quotedPattern = false;
                }
            } else if (current == ';'
                    && (readingColumn
                            || (groupDepth == 0 && characterClasses.isEmpty() && !quotedPattern))) {
                addMapping(columns, table, column, readingColumn);
                table.setLength(0);
                column.setLength(0);
                readingColumn = false;
            } else if (current == ':'
                    && !readingColumn
                    && groupDepth == 0
                    && characterClasses.isEmpty()
                    && !quotedPattern) {
                readingColumn = true;
            } else {
                if (!readingColumn && !quotedPattern) {
                    if (current == '[') {
                        characterClasses.push(index);
                    } else if (current == ']' && !characterClasses.isEmpty()) {
                        int start = characterClasses.peek();
                        if (index != start + 1
                                && !(index == start + 2 && value.charAt(start + 1) == '^')) {
                            characterClasses.pop();
                        }
                    } else if (characterClasses.isEmpty() && current == '(') {
                        groupDepth++;
                    } else if (characterClasses.isEmpty() && current == ')') {
                        checkArgument(groupDepth > 0, "Unbalanced table pattern parentheses.");
                        groupDepth--;
                    }
                }
                target.append(current);
            }
        }
        checkArgument(
                groupDepth == 0 && characterClasses.isEmpty() && !quotedPattern,
                "Unbalanced table pattern.");
        if (readingColumn || !table.toString().trim().isEmpty()) {
            addMapping(columns, table, column, readingColumn);
        }
        checkArgument(!columns.isEmpty(), "Table chunk keys must not be empty.");
        return columns;
    }

    public static Map<ObjectPath, String> parseObjectPaths(String value) {
        Map<ObjectPath, String> columns = new HashMap<>();
        for (Map.Entry<String, String> entry : parse(value).entrySet()) {
            String name = entry.getKey();
            int separator = -1;
            for (int index = 0; index < name.length(); index++) {
                if (name.charAt(index) == '\\') {
                    index++;
                } else if (name.charAt(index) == '.') {
                    checkArgument(separator < 0, "Expected a 'schema.table' path: %s", name);
                    separator = index;
                }
            }
            checkArgument(
                    separator > 0 && separator < name.length() - 1,
                    "Expected a 'schema.table' path: %s",
                    name);
            ObjectPath path =
                    new ObjectPath(
                            unescapeIdentifier(name.substring(0, separator).trim()),
                            unescapeIdentifier(name.substring(separator + 1).trim()));
            checkArgument(
                    columns.putIfAbsent(path, entry.getValue()) == null,
                    "Duplicate chunk key configuration for table '%s'.",
                    path);
        }
        return columns;
    }

    private static void addMapping(
            Map<String, String> columns,
            StringBuilder table,
            StringBuilder column,
            boolean hasSeparator) {
        String tableName = table.toString().trim();
        String columnName = column.toString().trim();
        checkArgument(
                hasSeparator && !tableName.isEmpty() && !columnName.isEmpty(),
                "Expected 'table:column' entries separated by ';'.");
        checkArgument(
                columns.putIfAbsent(tableName, columnName) == null,
                "Duplicate chunk key configuration for table '%s'.",
                tableName);
    }

    private static String unescapeIdentifier(String value) {
        StringBuilder result = new StringBuilder();
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            if (current == '\\'
                    && index + 1 < value.length()
                    && ";:\\.()[]".indexOf(value.charAt(index + 1)) >= 0) {
                current = value.charAt(++index);
            }
            result.append(current);
        }
        return result.toString();
    }
}
