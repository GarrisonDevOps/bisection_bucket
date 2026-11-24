# frozen_string_literal: true

module AntiAbuse
  class UserMetadata < ApplicationRecord
    self.table_name = 'abuse_metadata'
    self.primary_key = :user_id

    METRICS = %w[top_level_groups_created_count].freeze

    belongs_to :user

    validates :metadata, json_schema: { filename: 'abuse_metadata', size_limit: 64.kilobytes }

    class << self
      def metric(user_id, key)
        where(user_id: user_id).pick(Arel.sql(sanitize_sql(['(metadata ->> ?)::integer', metric_key(key)])))
      end

      def initialize_metric(user_id, key, value)
        upsert(
          { user_id: user_id, metadata: { metric_key(key) => value } },
          unique_by: :user_id,
          on_duplicate: Arel.sql('metadata = EXCLUDED.metadata || abuse_metadata.metadata, updated_at = NOW()')
        )
      end

      def increment_metric(user_id, key, initial:)
        key = metric_key(key)

        upsert(
          { user_id: user_id, metadata: { key => initial + 1 } },
          unique_by: :user_id,
          on_duplicate: Arel.sql(sanitize_sql([<<~SQL, { key: key, initial: initial }]))
            metadata = abuse_metadata.metadata ||
              jsonb_build_object(:key, COALESCE((abuse_metadata.metadata ->> :key)::integer, :initial) + 1),
            updated_at = NOW()
          SQL
        )
      end

      private

      def metric_key(key)
        key = key.to_s
        raise ArgumentError, "Unknown abuse metric: #{key}" unless METRICS.include?(key)

        key
      end
    end
  end
end
