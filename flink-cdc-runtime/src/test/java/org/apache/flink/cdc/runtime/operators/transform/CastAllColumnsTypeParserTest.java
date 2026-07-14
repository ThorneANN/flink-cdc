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

import org.apache.flink.cdc.common.types.DataTypes;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;

/** Unit tests for {@link CastAllColumnsTypeParser}. */
class CastAllColumnsTypeParserTest {

    @Test
    void testParseSimpleTypes() {
        Assertions.assertThat(CastAllColumnsTypeParser.parse("STRING"))
                .isEqualTo(DataTypes.STRING());
        Assertions.assertThat(CastAllColumnsTypeParser.parse("BOOLEAN"))
                .isEqualTo(DataTypes.BOOLEAN());
        Assertions.assertThat(CastAllColumnsTypeParser.parse("INT")).isEqualTo(DataTypes.INT());
        Assertions.assertThat(CastAllColumnsTypeParser.parse("INTEGER")).isEqualTo(DataTypes.INT());
        Assertions.assertThat(CastAllColumnsTypeParser.parse("BIGINT"))
                .isEqualTo(DataTypes.BIGINT());
    }

    @Test
    void testParseParameterizedTypes() {
        Assertions.assertThat(CastAllColumnsTypeParser.parse("VARCHAR(1024)"))
                .isEqualTo(DataTypes.VARCHAR(1024));
        Assertions.assertThat(CastAllColumnsTypeParser.parse("CHAR(8)"))
                .isEqualTo(DataTypes.CHAR(8));
        Assertions.assertThat(CastAllColumnsTypeParser.parse("DECIMAL(10,2)"))
                .isEqualTo(DataTypes.DECIMAL(10, 2));
        Assertions.assertThat(CastAllColumnsTypeParser.parse("TIMESTAMP(3)"))
                .isEqualTo(DataTypes.TIMESTAMP(3));
    }

    @Test
    void testParseIsCaseInsensitiveAndWhitespaceTolerant() {
        Assertions.assertThat(CastAllColumnsTypeParser.parse(" string "))
                .isEqualTo(DataTypes.STRING());
        Assertions.assertThat(CastAllColumnsTypeParser.parse(" varchar ( 255 ) "))
                .isEqualTo(DataTypes.VARCHAR(255));
    }

    @Test
    void testParseThrowsOnUnsupportedType() {
        Assertions.assertThatThrownBy(() -> CastAllColumnsTypeParser.parse("ARRAY"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported type");
    }

    @Test
    void testCastValueToString() {
        Assertions.assertThat(CastAllColumnsTypeParser.castValue(42, DataTypes.STRING()))
                .isEqualTo("42");
        Assertions.assertThat(CastAllColumnsTypeParser.castValue(true, DataTypes.STRING()))
                .isEqualTo("true");
        Assertions.assertThat(
                        CastAllColumnsTypeParser.castValue(
                                new BigDecimal("123.45"), DataTypes.STRING()))
                .isEqualTo("123.45");
        Assertions.assertThat(CastAllColumnsTypeParser.castValue(null, DataTypes.STRING()))
                .isNull();
    }

    @Test
    void testCastValueToNumericTypes() {
        Assertions.assertThat(CastAllColumnsTypeParser.castValue("42", DataTypes.BIGINT()))
                .isEqualTo(42L);
        Assertions.assertThat(CastAllColumnsTypeParser.castValue("42", DataTypes.INT()))
                .isEqualTo(42);
        Assertions.assertThat(CastAllColumnsTypeParser.castValue("3.14", DataTypes.DOUBLE()))
                .isEqualTo(3.14d);
        Object decimalResult =
                CastAllColumnsTypeParser.castValue("123.45", DataTypes.DECIMAL(10, 2));
        Assertions.assertThat(decimalResult).isInstanceOf(BigDecimal.class);
        Assertions.assertThat(((BigDecimal) decimalResult))
                .isEqualByComparingTo(new BigDecimal("123.45"));
    }
}
