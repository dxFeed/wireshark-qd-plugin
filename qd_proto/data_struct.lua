-- @file data_struct.lua
-- @brief Types and structures.
local data_struct = {}

-- List of QD message type.
data_struct.qd_type = {
    HEARTBEAT = 0,
    DESCRIBE_PROTOCOL = 1,
    DESCRIBE_RECORDS = 2,
    PART = 4,
    RAW_DATA = 5,
    TICKER_DATA = 10,
    TICKER_ADD_SUBSCRIPTION = 11,
    TICKER_REMOVE_SUBSCRIPTION = 12,
    STREAM_DATA = 15,
    STREAM_ADD_SUBSCRIPTION = 16,
    STREAM_REMOVE_SUBSCRIPTION = 17,
    HISTORY_DATA = 20,
    HISTORY_ADD_SUBSCRIPTION = 21,
    HISTORY_REMOVE_SUBSCRIPTION = 22,
    RMI_ADVERTISE_SERVICES = 49,
    RMI_DESCRIBE_SUBJECT = 50,
    RMI_DESCRIBE_OPERATION = 51,
    RMI_REQUEST = 52,
    RMI_CANCEL = 53,
    RMI_RESULT = 54,
    RMI_ERROR = 55,
    RMI_RESPONSE = 56
}

-- Base field type.
data_struct.field_base = {
    VOID = 0,
    BYTE = 1,
    UTF_CHAR = 2,
    SHORT = 3,
    INT = 4,
    -- Ids 5-7 are reserved for future use.
    COMPACT_INT = 8,
    BYTE_ARRAY = 9,
    UTF_CHAR_ARRAY = 10
    -- Ids 11-15 are reserved for future use.
}

-- Field flag for type.
data_struct.field_flag = {
    -- Plain int as int field.
    INT = 0x00,
    -- Decimal representation as int field.
    DECIMAL = 0x10,
    -- Short (up to 4-character) string representation as int field.
    SHORT_STRING = 0x20,
    -- Time in seconds as integer field.
    TIME_SECONDS = 0x30,
    -- Sequence in this integer fields (with top 10 bits representing millis).
    SEQUENCE = 0x40,
    -- Day id in this integer field.
    DATE = 0x50,
    -- Plain long as two int fields.
    LONG = 0x60,
    -- WideDecimal representation as long field.
    WIDE_DECIMAL = 0x70,
    -- String representation as byte array (for ID_BYTE_ARRAY).
    STRING = 0x80,
    -- Time in millis as long field.
    TIME_MILLISECONDS = 0x90,
    -- Reserved for future use: time in nanoseconds as long field.
    TIME_NANOSECONDS = 0xA0,
    -- Custom serialized object as byte array (for ID_BYTE_ARRAY).
    CUSTOM_OBJECT = 0xE0,
    -- Serialized object as byte array (for ID_BYTE_ARRAY).
    SERIAL_OBJECT = 0xF0
}

-- Mask for filed type.
data_struct.field_mask = {SERIALIZATION = 0x0F, REPRESENTATION = 0xF0}

-- List of field type.
data_struct.field_type = {
    VOID = data_struct.field_base.VOID,
    BYTE = data_struct.field_base.BYTE,
    UTF_CHAR = data_struct.field_base.UTF_CHAR,
    SHORT = data_struct.field_base.SHORT,
    INT = data_struct.field_base.INT,
    COMPACT_INT = data_struct.field_base.COMPACT_INT,
    BYTE_ARRAY = data_struct.field_base.BYTE_ARRAY,
    UTF_CHAR_ARRAY = data_struct.field_base.UTF_CHAR_ARRAY,
    DECIMAL = bit.bor(data_struct.field_base.COMPACT_INT,
                      data_struct.field_flag.DECIMAL),
    SHORT_STRING = bit.bor(data_struct.field_base.COMPACT_INT,
                           data_struct.field_flag.SHORT_STRING),
    TIME_SECONDS = bit.bor(data_struct.field_base.COMPACT_INT,
                           data_struct.field_flag.TIME_SECONDS),
    TIME_MILLISECONDS = bit.bor(data_struct.field_base.COMPACT_INT,
                                data_struct.field_flag.TIME_MILLISECONDS),
    TIME_NANOSECONDS = bit.bor(data_struct.field_base.COMPACT_INT,
                               data_struct.field_flag.TIME_NANOSECONDS),
    SEQUENCE = bit.bor(data_struct.field_base.COMPACT_INT,
                       data_struct.field_flag.SEQUENCE),
    DATE = bit.bor(data_struct.field_base.COMPACT_INT,
                   data_struct.field_flag.DATE),
    LONG = bit.bor(data_struct.field_base.COMPACT_INT,
                   data_struct.field_flag.LONG),
    WIDE_DECIMAL = bit.bor(data_struct.field_base.COMPACT_INT,
                           data_struct.field_flag.WIDE_DECIMAL),
    STRING = bit.bor(data_struct.field_base.BYTE_ARRAY,
                     data_struct.field_flag.STRING),
    CUSTOM_OBJECT = bit.bor(data_struct.field_base.BYTE_ARRAY,
                            data_struct.field_flag.CUSTOM_OBJECT),
    SERIAL_OBJECT = bit.bor(data_struct.field_base.BYTE_ARRAY,
                            data_struct.field_flag.SERIAL_OBJECT)
}

-- List of event flags that can be passed along with the symbol.
data_struct.event_flags = {
    -- (0x01) TX_PENDING indicates a pending transactional update.
    -- When TX_PENDING is 1, it means that an ongoing transaction
    -- update, that spans multiple events, is in process
    TX_PENDING = 0x01,
    -- (0x02) REMOVE_EVENT indicates that the event with the
    -- corresponding index has to be removed
    REMOVE_EVENT = 0x02,
    -- (0x04) SNAPSHOT_BEGIN indicates when the loading of a snapshot starts.
    -- Snapshot load starts on new subscription and the first indexed event
    -- that arrives for each exchange code (in the case of a regional record)
    -- on a new subscription may have SNAPSHOT_BEGIN set to true. It means
    -- that an ongoing snapshot consisting of multiple events is incoming
    SNAPSHOT_BEGIN = 0x04,
    -- (0x08) SNAPSHOT_END or (0x10) SNAPSHOT_SNIP indicates the end of a
    -- snapshot. The difference between SNAPSHOT_END and SNAPSHOT_SNIP is the
    -- following: SNAPSHOT_END indicates that the data source sent all the data
    -- pertaining to the subscription for the corresponding indexed event, while
    -- SNAPSHOT_SNIP indicates that some limit on the amount of data was reached
    -- and while there still might be more data available, it will not be
    -- provided
    SNAPSHOT_END = 0x08,
    SNAPSHOT_SNIP = 0x10,
    RESERVED = 0x20,
    SNAPSHOT_MODE = 0x40,
    REMOVE_SYMBOL = 0x80
}

return data_struct
