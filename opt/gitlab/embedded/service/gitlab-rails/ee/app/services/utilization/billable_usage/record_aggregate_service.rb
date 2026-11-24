# frozen_string_literal: true

module Utilization
  module BillableUsage
    # Folds a single billable event into the day's aggregate row.
    #
    # Every event of a type on a day targets one row, so concurrent writes serialise on
    # a single tuple. Fine at Secrets Manager volume; Duo Agent Platform would need to
    # batch behind a job first.
    class RecordAggregateService
      include ::Gitlab::Utils::StrongMemoize

      UNIQUE_BY = %i[usage_date event_type feature_qualified_name operation_type root_namespace_id].freeze

      TABLE = 'billable_usage_daily_namespace_aggregates'

      ON_DUPLICATE = {
        ::Gitlab::BillingEvents::Client::COUNTER => <<~SQL.squish,
          quantity = #{TABLE}.quantity + EXCLUDED.quantity,
          events_count = #{TABLE}.events_count + EXCLUDED.events_count,
          updated_at = EXCLUDED.updated_at
        SQL
        ::Gitlab::BillingEvents::Client::SNAPSHOT => <<~SQL.squish
          quantity = EXCLUDED.quantity,
          events_count = #{TABLE}.events_count + EXCLUDED.events_count,
          updated_at = EXCLUDED.updated_at
        SQL
      }.freeze

      def initialize(context, quantity_kind:, events_count: 1)
        @context = context
        @quantity_kind = quantity_kind
        @events_count = events_count
      end

      def execute
        return log_missing_feature_qualified_name if feature_qualified_name.blank?

        record = DailyNamespaceAggregate.new(attributes)
        return log_invalid(record) unless record.valid?

        DailyNamespaceAggregate.upsert_all(
          [attributes],
          unique_by: UNIQUE_BY,
          on_duplicate: Arel.sql(ON_DUPLICATE.fetch(quantity_kind))
        )
      end

      private

      attr_reader :context, :quantity_kind, :events_count

      def attributes
        {
          **unique_key_values,
          unit_of_measure: context[:unit_of_measure],
          quantity: context[:quantity],
          events_count: events_count
        }
      end
      strong_memoize_attr :attributes

      def unique_key_values
        {
          usage_date: usage_date,
          event_type: context[:event_type],
          feature_qualified_name: feature_qualified_name,
          operation_type: operation_type,
          root_namespace_id: context[:root_namespace_id]
        }
      end
      strong_memoize_attr :unique_key_values

      def usage_date
        Time.zone.parse(context[:timestamp].to_s).utc.to_date
      end
      strong_memoize_attr :usage_date

      def metadata
        (context[:metadata] || {}).deep_stringify_keys
      end
      strong_memoize_attr :metadata

      def feature_qualified_name
        metadata['feature_qualified_name']
      end

      def operation_type
        metadata['operation_type']
      end

      # Logged rather than raised: the caller swallows exceptions into error tracking.
      def log_missing_feature_qualified_name
        ::Gitlab::AppLogger.error(
          message: 'BillingEvents: aggregate not recorded, metadata.feature_qualified_name is missing',
          event_type: context[:event_type]
        )
      end

      def log_invalid(record)
        ::Gitlab::AppLogger.error(
          message: 'BillingEvents: aggregate not recorded, record is invalid',
          event_type: context[:event_type],
          errors: record.errors.full_messages
        )
      end
    end
  end
end
