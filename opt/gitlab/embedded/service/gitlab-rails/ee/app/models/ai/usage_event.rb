# frozen_string_literal: true

module Ai
  class UsageEvent < ApplicationRecord
    include ClickHouseModel
    include PartitionedTable
    include Analytics::HasWriteBuffer

    self.table_name = "ai_usage_events"
    self.clickhouse_table_name = "ai_usage_events"

    partitioned_by :timestamp, strategy: :monthly, retain_for: 3.months
    self.primary_key = :id

    # Partitions are only created a few months ahead. A row beyond them fails the whole
    # write buffer batch, so reject client timestamps past a small clock skew.
    MAX_FUTURE_TIMESTAMP_SKEW = 1.day

    # Falls back to the Default Organization for a nil user - deliberate, temporary
    # regression, see https://gitlab.com/gitlab-org/gitlab/-/issues/610965.
    populate_sharding_key(:organization_id) do
      user&.organization_id || Organizations::Organization::DEFAULT_ORGANIZATION_ID # rubocop:todo Gitlab/AvoidConstDefaultOrganizationId -- see comment above
    end

    self.write_buffer_options = { class: Analytics::LegacyAiUsageDatabaseWriteBuffer }

    belongs_to :user
    belongs_to :organization, class_name: 'Organizations::Organization'
    belongs_to :namespace, optional: true
    attribute :timestamp, :datetime, default: -> { DateTime.current }

    enum :event, Gitlab::Tracking::AiTracking.registered_events

    validates :timestamp, :user_id, :organization_id, presence: true
    validates :namespace, presence: true, if: :namespace_id?
    validates :extras, json_schema: { filename: "ai_usage_event_extras", size_limit: 16.kilobytes }
    validate :validate_recent_timestamp, on: :create
    validate :validate_event_status, on: :create

    before_validation :floor_timestamp

    scope :with_namespace, -> { includes(:namespace) }
    scope :sort_by_timestamp_id, ->(dir: :desc) { order(timestamp: dir, id: dir) }

    scope :in_timeframe, ->(range) { where(timestamp: range) }
    scope :with_events, ->(event_names) { where(event: event_names) }
    scope :with_users, ->(users) { where(user: users) }
    scope :for_namespace_hierarchy, ->(namespace) do
      base_usage_events = order_values.any? ? self : sort_by_timestamp_id
      base_usage_events.where(namespace_id: namespace.self_and_descendant_ids(skope: Namespace))
    end

    def store_to_pg
      return false unless valid?

      attrs = attributes_for_database.compact
      attrs['extras'] = attributes['extras'] # preserve JSON type for extras

      self.class.write_buffer.add(attrs)

      true
    end

    def to_clickhouse_csv_row
      {
        event: self.class.events[event],
        # we round to 3 digits here to avoid floating number inconsistencies.
        # until https://gitlab.com/gitlab-org/gitlab/-/issues/527129
        # is resolved
        timestamp: Time.zone.parse(timestamp.as_json).to_f.round(3),
        user_id: user&.id,
        # `namespace_path` is deprecated in favour of the org-scoped `traversal_path`, but is still
        # forwarded by materialized views into tables not yet migrated. See
        # https://gitlab.com/gitlab-org/gitlab/-/issues/603734
        namespace_path: namespace&.traversal_path(with_organization: false),
        traversal_path: namespace&.traversal_path(with_organization: true),
        extras: extras.to_json
      }
    end

    private

    def floor_timestamp
      # we floor to 3 digits here to match current JSON rounding used in Write Buffers.
      # That creates consistency between PG and CH until https://gitlab.com/gitlab-org/gitlab/-/issues/527129
      # is resolved
      self.timestamp = timestamp&.floor(3)
    end

    def validate_recent_timestamp
      return unless timestamp

      if timestamp < self.class.partitioning_strategy.retain_for.ago
        errors.add(:timestamp, _('must be 3 months old at the most'))
      elsif timestamp > MAX_FUTURE_TIMESTAMP_SKEW.from_now
        errors.add(:timestamp, _('must be 1 day in the future at the most'))
      end
    end

    def validate_event_status
      return unless Gitlab::Tracking::AiTracking.deprecated_event?(event)

      errors.add(:event, _('is read-only'))
    end
  end
end
