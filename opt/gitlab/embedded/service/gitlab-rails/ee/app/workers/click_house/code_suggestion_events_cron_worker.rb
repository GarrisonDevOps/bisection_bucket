# frozen_string_literal: true

module ClickHouse # rubocop:disable Gitlab/BoundedContexts -- this file will be removed in next release.
  # Alias worker class. Remove after 17.8 release so scheduled cron jobs can work-off properly
  class CodeSuggestionEventsCronWorker < DumpAllWriteBuffersCronWorker
    idempotent!
    tags :clickhouse

    def perform
      # no-op
    end
  end
end
