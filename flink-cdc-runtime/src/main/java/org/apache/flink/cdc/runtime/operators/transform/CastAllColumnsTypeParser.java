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

package org.apache.flink.cdc.runtime.operators.transform;

import org.apache.flink.cdc.common.types.DataType;
import org.apache.flink.cdc.common.types.DataTypes;
import org.apache.flink.cdc.common.types.DecimalType;
import org.apache.flink.cdc.runtime.functions.impl.CastingFunctions;

import java.math.BigDecimal;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility for parsing type-name strings (e.g. {@code "STRING"}, {@code "VARCHAR(1024)"}, {@code
 * "BIGINT"}) into {@link DataType} instances, and for casting Java-layer values to those types.
 *
 * <p>Used by {@link PostTransformOperator} to support the {@code cast-all-columns-to} configuration
 * option in transform rules.
 */
public class CastAllColumnsTypeParser {

    /** Matches parameterized types such as {@code VARCHAR(1024)} or {@code DECIMAL(10,2)}. */
    private static final Pattern PARAMETERIZED_TYPE =
            Pattern.compile("^(\\w+)\\s*\\(\\s*(\\d+)(?:\\s*,\\s*(\\d+))?\\s*\\)$");

    /**
     * Parses a type-name string into a {@link DataType}.
     *
     * <p>Supported formats (case-insensitive):
     *
     * <ul>
     *   <li>{@code STRING} → unbounded VARCHAR
     *   <li>{@code VARCHAR(n)} → VarCharType of length n
     *   <li>{@code CHAR(n)} → CharType of length n
     *   <li>{@code BOOLEAN}
     *   <li>{@code TINYINT}
     *   <li>{@code SMALLINT}
     *   <li>{@code INT} / {@code INTEGER}
     *   <li>{@code BIGINT}
     *   <li>{@code FLOAT}
     *   <li>{@code DOUBLE}
     *   <li>{@code DECIMAL(p,s)}
     *   <li>{@code DATE}
     *   <li>{@code TIME} / {@code TIME(p)}
     *   <li>{@code TIMESTAMP} / {@code TIMESTAMP(p)}
     * </ul>
     *
     * @param typeStr the type-name string from the pipeline YAML
     * @return the corresponding {@link DataType}
     * @throws IllegalArgumentException for unrecognized or unsupported type strings
     */
    public static DataType parse(String typeStr) {
        if (typeStr == null || typeStr.trim().isEmpty()) {
            throw new IllegalArgumentException(
                    "cast-all-columns-to type string must not be null or blank");
        }
        String upper = typeStr.trim().toUpperCase();

        // Try parameterized form first: TYPE(p1) or TYPE(p1, p2)
        Matcher m = PARAMETERIZED_TYPE.matcher(upper);
        if (m.matches()) {
            String typeName = m.group(1);
            int p1 = Integer.parseInt(m.group(2));
            String g3 = m.group(3);
            int p2 = (g3 != null) ? Integer.parseInt(g3) : -1;

            switch (typeName) {
                case "VARCHAR":
                    return DataTypes.VARCHAR(p1);
                case "CHAR":
                    return DataTypes.CHAR(p1);
                case "VARBINARY":
                    return DataTypes.VARBINARY(p1);
                case "BINARY":
                    return DataTypes.BINARY(p1);
                case "DECIMAL":
                    return DataTypes.DECIMAL(p1, (p2 >= 0) ? p2 : 0);
                case "TIMESTAMP":
                    return DataTypes.TIMESTAMP(p1);
                case "TIME":
                    return DataTypes.TIME(p1);
                default:
                    throw new IllegalArgumentException(
                            "Unsupported parameterized type in cast-all-columns-to: "
                                    + typeStr
                                    + ". Supported parameterized types: VARCHAR(n), CHAR(n),"
                                    + " DECIMAL(p,s), TIMESTAMP(p), TIME(p)");
            }
        }

        // Simple (no-parameter) types
        switch (upper) {
            case "STRING":
                return DataTypes.STRING();
            case "BOOLEAN":
                return DataTypes.BOOLEAN();
            case "TINYINT":
                return DataTypes.TINYINT();
            case "SMALLINT":
                return DataTypes.SMALLINT();
            case "INT":
            case "INTEGER":
                return DataTypes.INT();
            case "BIGINT":
                return DataTypes.BIGINT();
            case "FLOAT":
                return DataTypes.FLOAT();
            case "DOUBLE":
                return DataTypes.DOUBLE();
            case "DECIMAL":
                return DataTypes.DECIMAL(DecimalType.DEFAULT_PRECISION, DecimalType.DEFAULT_SCALE);
            case "DATE":
                return DataTypes.DATE();
            case "TIMESTAMP":
                return DataTypes.TIMESTAMP();
            case "TIME":
                return DataTypes.TIME();
            default:
                throw new IllegalArgumentException(
                        "Unsupported type in cast-all-columns-to: '"
                                + typeStr
                                + "'. Supported types: STRING, VARCHAR(n), CHAR(n), BOOLEAN,"
                                + " TINYINT, SMALLINT, INT, BIGINT, FLOAT, DOUBLE,"
                                + " DECIMAL(p,s), DATE, TIMESTAMP, TIME");
        }
    }

    /**
     * Casts a Java-layer value (already converted via {@code JavaObjectConverter.convertToJava}) to
     * the given target type, returning a Java-layer value suitable for passing to {@code
     * BinaryInternalObjectConverter.convertToInternal}.
     *
     * <p>Null inputs are returned as null (null-safe). Cast failures (e.g. unparseable strings)
     * return null rather than throwing, consistent with {@link CastingFunctions} behaviour.
     *
     * @param value the source value in Java representation (may be null)
     * @param target the target {@link DataType}
     * @return the cast value in Java representation, or {@code null} if input is null
     * @throws UnsupportedOperationException for target types not supported by this utility
     */
    public static Object castValue(Object value, DataType target) {
        if (value == null) {
            return null;
        }
        switch (target.getTypeRoot()) {
            case VARCHAR:
            case CHAR:
                return CastingFunctions.castToString(value);
            case BOOLEAN:
                return CastingFunctions.castToBoolean(value);
            case TINYINT:
                return CastingFunctions.castToByte(value);
            case SMALLINT:
                return CastingFunctions.castToShort(value);
            case INTEGER:
                return CastingFunctions.castToInteger(value);
            case BIGINT:
                return CastingFunctions.castToLong(value);
            case FLOAT:
                return CastingFunctions.castToFloat(value);
            case DOUBLE:
                return CastingFunctions.castToDouble(value);
            case DECIMAL:
                DecimalType dt = (DecimalType) target;
                BigDecimal bd =
                        CastingFunctions.castToBigDecimal(value, dt.getPrecision(), dt.getScale());
                return bd;
            case DATE:
            case TIME_WITHOUT_TIME_ZONE:
            case TIMESTAMP_WITHOUT_TIME_ZONE:
            case TIMESTAMP_WITH_LOCAL_TIME_ZONE:
            case TIMESTAMP_WITH_TIME_ZONE:
                // Temporal types pass through; casting from non-temporal sources to temporal
                // requires timezone context unavailable here. Use projection CAST() for that.
                return value;
            default:
                throw new UnsupportedOperationException(
                        "cast-all-columns-to does not support target type: "
                                + target.getTypeRoot()
                                + ". Use STRING, numeric, or temporal target types.");
        }
    }
}
