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
import org.apache.flink.cdc.common.utils.Predicates;
import org.apache.flink.table.catalog.ObjectPath;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import static org.apache.flink.util.Preconditions.checkArgument;
import static org.apache.flink.util.Preconditions.checkNotNull;

/** Parses table-to-column mappings shared by the DataStream and Pipeline sources. */
@Internal
public final class SqlServerChunkKeyColumnParser {

    private SqlServerChunkKeyColumnParser() {}

    /** Parses mappings whose table keys follow the Pipeline regular-expression syntax. */
    public static Map<String, String> parse(String value) {
        return parse(value, true);
    }

    /** Parses candidate Pipeline mappings; the caller resolves ambiguous physical column names. */
    public static Map<String, String> parseOption(String value) {
        return parse(value, true, true);
    }

    private static Map<String, String> parse(String value, boolean regularExpressions) {
        return parse(value, regularExpressions, false);
    }

    private static Map<String, String> parse(
            String value, boolean regularExpressions, boolean allowColumnName) {
        checkNotNull(value, "Table chunk keys must not be null.");
        Map<String, String> columns = new HashMap<>();
        StringBuilder table = new StringBuilder();
        StringBuilder column = new StringBuilder();
        boolean readingColumn = false;
        boolean mappingStarted = !allowColumnName;
        RegexContext regex = regularExpressions ? new RegexContext() : null;
        try {
            for (int index = 0; index < value.length(); index++) {
                char current = value.charAt(index);
                StringBuilder target = readingColumn ? column : table;
                if (!readingColumn && regex != null && regex.comment) {
                    table.append(current);
                    regex.acceptComment(current);
                    continue;
                }
                if (!readingColumn && regex != null && regex.quoted) {
                    table.append(current);
                    if (current == '\\'
                            && index + 1 < value.length()
                            && value.charAt(index + 1) == 'E') {
                        table.append(value.charAt(++index));
                        regex.quoted = false;
                    } else {
                        regex.acceptLiteral();
                    }
                    continue;
                }
                if (current == '\\') {
                    checkArgument(index + 1 < value.length(), "Unterminated chunk key escape.");
                    char escaped = value.charAt(++index);
                    if (!readingColumn || ";:\\".indexOf(escaped) < 0) {
                        target.append('\\');
                    }
                    target.append(escaped);
                    if (!readingColumn && regex != null) {
                        if (escaped == 'Q') {
                            regex.quoted = true;
                        } else {
                            regex.acceptLiteral();
                        }
                    }
                } else if (current == ';'
                        && (readingColumn || regex == null || regex.atBoundary())) {
                    if (!mappingStarted) {
                        return Collections.emptyMap();
                    }
                    addMapping(columns, table, column, readingColumn);
                    table.setLength(0);
                    column.setLength(0);
                    readingColumn = false;
                    if (regex != null) {
                        regex.reset();
                    }
                } else if (current == ':'
                        && !readingColumn
                        && (regex == null || regex.atBoundary())) {
                    if (!mappingStarted) {
                        String[] patterns = Predicates.RegExSplitterByComma.split(table.toString());
                        if (patterns.length == 0
                                || Arrays.stream(patterns)
                                        .anyMatch(
                                                pattern ->
                                                        Predicates.RegExSplitterByDot.split(pattern)
                                                                        .length
                                                                != 3)) {
                            return Collections.emptyMap();
                        }
                        mappingStarted = true;
                    }
                    readingColumn = true;
                } else if (!readingColumn && regex != null) {
                    int last = regex.accept(value, index);
                    table.append(value, index, last + 1);
                    index = last;
                } else {
                    target.append(current);
                }
            }
            if (!mappingStarted) {
                return Collections.emptyMap();
            }
            checkArgument(regex == null || regex.balanced(), "Unbalanced table pattern.");
            if (readingColumn || !table.toString().trim().isEmpty()) {
                addMapping(columns, table, column, readingColumn);
            }
            checkArgument(!columns.isEmpty(), "Table chunk keys must not be empty.");
            return columns;
        } catch (IllegalArgumentException e) {
            if (mappingStarted) {
                throw e;
            }
            return Collections.emptyMap();
        }
    }

    /** Parses mappings with literal schema and table names for the Java Source. */
    public static Map<ObjectPath, String> parseObjectPaths(String value) {
        Map<ObjectPath, String> columns = new HashMap<>();
        for (Map.Entry<String, String> entry : parse(value, false).entrySet()) {
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

    private static final class RegexContext {
        private final Deque<Integer> groups = new ArrayDeque<>();
        private final Deque<CharacterClass> characterClasses = new ArrayDeque<>();
        private int flags;
        private boolean comment;
        private boolean quoted;

        private boolean atBoundary() {
            return groups.isEmpty() && characterClasses.isEmpty() && !comment && !quoted;
        }

        private boolean balanced() {
            return groups.isEmpty() && characterClasses.isEmpty() && !quoted;
        }

        private void reset() {
            groups.clear();
            characterClasses.clear();
            flags = 0;
            comment = false;
            quoted = false;
        }

        private void acceptComment(char current) {
            if (isLineSeparator(current, flags)) {
                comment = false;
                if (!isWhitespace(current)) {
                    acceptLiteral();
                }
            }
        }

        private void acceptLiteral() {
            if (!characterClasses.isEmpty()) {
                characterClasses.peek().canClose = true;
            }
        }

        private int accept(String value, int index) {
            char current = value.charAt(index);
            if ((flags & Pattern.COMMENTS) != 0) {
                if (current == '#') {
                    comment = true;
                    return index;
                }
                if (isWhitespace(current)) {
                    return index;
                }
            }
            if (current == '[') {
                acceptLiteral();
                characterClasses.push(new CharacterClass());
            } else if (!characterClasses.isEmpty()) {
                CharacterClass characterClass = characterClasses.peek();
                if (current == ']' && characterClass.canClose) {
                    characterClasses.pop();
                } else if (current == '^' && !characterClass.canClose && !characterClass.negated) {
                    characterClass.negated = true;
                } else {
                    acceptLiteral();
                }
            } else if (current == '(') {
                int last = acceptFlags(value, index);
                if (last != index) {
                    return last;
                }
                groups.push(flags);
            } else if (current == ')') {
                checkArgument(!groups.isEmpty(), "Unbalanced table pattern parentheses.");
                flags = groups.pop();
            } else if (current == '.' && groups.isEmpty()) {
                // Each namespace/schema/table component is compiled as a separate regex.
                flags = 0;
            }
            return index;
        }

        private int acceptFlags(String value, int index) {
            if (index + 1 >= value.length() || value.charAt(index + 1) != '?') {
                return index;
            }
            int updatedFlags = flags;
            boolean subtract = false;
            boolean foundFlag = false;
            int cursor = index + 2;
            while (cursor < value.length()) {
                char current = value.charAt(cursor);
                if ((updatedFlags & Pattern.COMMENTS) != 0) {
                    if (isWhitespace(current)) {
                        cursor++;
                        continue;
                    }
                    if (current == '#') {
                        cursor++;
                        while (cursor < value.length()
                                && !isLineSeparator(value.charAt(cursor), updatedFlags)) {
                            cursor++;
                        }
                        continue;
                    }
                }
                if (current == '-' && !subtract) {
                    subtract = true;
                } else if ("idmsucxU".indexOf(current) >= 0) {
                    foundFlag = true;
                    int flag = 0;
                    if (current == 'x') {
                        flag = Pattern.COMMENTS;
                    } else if (current == 'd') {
                        flag = Pattern.UNIX_LINES;
                    }
                    updatedFlags = subtract ? updatedFlags & ~flag : updatedFlags | flag;
                } else if (foundFlag && (current == ':' || current == ')')) {
                    if (current == ':') {
                        groups.push(flags);
                    }
                    flags = updatedFlags;
                    return cursor;
                } else {
                    return index;
                }
                cursor++;
            }
            return index;
        }

        private static boolean isWhitespace(char value) {
            return value == ' ' || (value >= '\t' && value <= '\r');
        }

        private static boolean isLineSeparator(char value, int flags) {
            return value == '\n'
                    || ((flags & Pattern.UNIX_LINES) == 0
                            && (value == '\r'
                                    || value == '\u0085'
                                    || value == '\u2028'
                                    || value == '\u2029'));
        }
    }

    private static final class CharacterClass {
        private boolean canClose;
        private boolean negated;
    }
}
