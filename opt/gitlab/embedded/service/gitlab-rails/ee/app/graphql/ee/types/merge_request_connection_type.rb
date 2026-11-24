# frozen_string_literal: true

module EE
  module Types
    module MergeRequestConnectionType # rubocop:disable Gitlab/BoundedContexts -- EE extension of the CE MergeRequestConnectionType
      extend ::Gitlab::Utils::Override

      private

      # Only cut the PostgreSQL count short where ClickHouse can serve throughput instead;
      # elsewhere the exact count is the only source.
      override :limit_count_time?
      def limit_count_time?
        super || ::Gitlab::Saas.feature_available?(:siphon_clickhouse_analytics)
      end
    end
  end
end
