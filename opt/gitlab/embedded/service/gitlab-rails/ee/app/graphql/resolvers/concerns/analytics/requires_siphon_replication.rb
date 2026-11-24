# frozen_string_literal: true

module Analytics
  # Guards analytics engines that read ClickHouse tables Siphon replicates. If ClickHouse isn't
  # configured or Siphon isn't enabled, those tables are empty, so the engines would silently
  # report zeros instead of erroring. Only checks the global Siphon flag, not whether
  # the specific table is replicated.
  module RequiresSiphonReplication
    # Stable machine-readable codes: the frontend keys panel states off these,
    # so renaming them breaks error classification in deployed frontends.
    CLICKHOUSE_NOT_CONFIGURED_CODE = 'CLICKHOUSE_NOT_CONFIGURED'
    SIPHON_REPLICATION_DISABLED_CODE = 'SIPHON_REPLICATION_DISABLED'

    def ready?(**args)
      unless ::Gitlab::ClickHouse.configured?
        raise_resource_not_available_error!(
          'ClickHouse is not configured on this instance.',
          { code: CLICKHOUSE_NOT_CONFIGURED_CODE }
        )
      end

      unless ::Gitlab::ClickHouse.siphon_enabled?
        raise_resource_not_available_error!(
          'Siphon replication is not enabled on this instance.',
          { code: SIPHON_REPLICATION_DISABLED_CODE }
        )
      end

      super
    end
  end
end
