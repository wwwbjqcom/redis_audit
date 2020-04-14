# redis_audit

CREATE table redis_audit.redis_audit_info(   source_host String,   source_port UInt64,   destination_host String,   destination_port UInt64,   command String,   event_date DateTime) ENGINE=MergeTree()   PARTITION BY toYYYYMMDD(event_date)   ORDER BY (source_host, source_port, event_date)   TTL event_date + INTERVAL 5 DAY   SETTINGS index_granularity=8192,enable_mixed_granularity_parts=1;
