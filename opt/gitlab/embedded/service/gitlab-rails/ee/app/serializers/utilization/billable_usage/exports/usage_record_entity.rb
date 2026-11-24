# frozen_string_literal: true

module Utilization
  module BillableUsage
    module Exports
      class UsageRecordEntity < Grape::Entity
        EVENT_ID_PREFIX = 'billable_usage_export'
        SNAPSHOT_EVENT_TYPES = [::SecretsManagement::BillableEvents::SecretsStoredEmitter::EVENT_TYPE].freeze

        expose :event_id
        expose :event_type
        expose :timestamp
        expose :quantity
        expose :unit_of_measure

        expose :metadata do
          expose :feature_qualified_name
          expose :operation_type, expose_nil: false
          expose :schema_version
          expose :events_count
          expose :quantity_kind
        end

        private

        # CustomersDot dedupes on this, so it must be stable per record and unique across
        # instances; the prefix keeps it distinct from other ids derived from the instance uuid.
        def event_id
          key = [object.usage_date, object.event_type, object.feature_qualified_name, object.operation_type].to_json

          Digest::UUID.uuid_v5(::Gitlab::GlobalAnonymousId.instance_uuid, "#{EVENT_ID_PREFIX}:#{key}")
        end

        # Midday rather than midnight, so applying a timezone downstream cannot move it
        # onto the previous or next day.
        def timestamp
          object.usage_date.to_time(:utc).change(hour: 12).iso8601
        end

        def quantity
          object.quantity.to_f
        end

        def events_count
          object.events_count.to_i
        end

        # Derived rather than read: the write path uses the kind only to fold a write into
        # the day's row, and never stores it.
        def quantity_kind
          return ::Gitlab::BillingEvents::Client::SNAPSHOT.to_s if SNAPSHOT_EVENT_TYPES.include?(object.event_type)

          ::Gitlab::BillingEvents::Client::COUNTER.to_s
        end

        delegate :event_type, :unit_of_measure, :feature_qualified_name, :operation_type,
          :schema_version, to: :object
      end
    end
  end
end
