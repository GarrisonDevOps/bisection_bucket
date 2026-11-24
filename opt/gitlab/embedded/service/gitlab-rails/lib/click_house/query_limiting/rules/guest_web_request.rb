# frozen_string_literal: true

module ClickHouse # rubocop:disable Gitlab/BoundedContexts -- existing module
  class QueryLimiting
    module Rules
      module GuestWebRequest
        SETTINGS = {
          max_rows_to_read: 10_000_000,
          max_bytes_to_read: 1.gigabyte,
          read_overflow_mode: 'break',
          max_execution_time: 5,
          timeout_overflow_mode: 'break',
          # 2 blocks persistent table writes and DDL but still allows
          # query-level SETTINGS clauses, unlike 1
          readonly: 2
        }.freeze

        def self.type = 'guest_web_request'
        def self.settings = SETTINGS

        def self.applies?(context)
          context&.get_attribute(Labkit::Fields::GL_USER_ID).nil? &&
            Gitlab::Runtime.puma? &&
            Feature.enabled?(:click_house_guest_query_limits, :instance)
        end
      end
    end
  end
end
