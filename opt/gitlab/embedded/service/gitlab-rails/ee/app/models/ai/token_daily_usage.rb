# frozen_string_literal: true

module Ai
  class TokenDailyUsage < ApplicationRecord
    include PartitionedTable
    include Analytics::HasWriteBuffer
    include ::Namespaces::Traversal::Traversable

    self.table_name = 'ai_token_daily_usages'
    self.primary_key = :id

    DEFAULT_RETENTION_DAYS = 1095
    FEATURES_BY_EVENT = { 'report_duo_chat_token_usage' => 'chat' }.freeze

    # Not Gitlab::CurrentSettings: a rake task with pending migrations can read it from defaults,
    # which would prune by the default period whatever an administrator set.
    partitioned_by :usage_date, strategy: :monthly,
      retain_for: -> { (::ApplicationSetting.current&.duo_token_usage_retention_days || DEFAULT_RETENTION_DAYS).days }

    populate_sharding_key(:organization_id) do
      next user&.organization_id if traversal_ids.blank?

      ::Namespace.find_by_id(traversal_ids.last)&.organization_id
    end

    belongs_to :user
    belongs_to :organization, class_name: 'Organizations::Organization'

    enum :feature, { chat: 0 }

    validates :usage_date, :user_id, :organization_id, :feature, :model, presence: true
    validates :model, length: { maximum: 255 }
    validates :input_tokens, :output_tokens, :events_count,
      numericality: { only_integer: true, greater_than_or_equal_to: 0 }
    validates :usage_date, on: :create, allow_nil: true,
      comparison: {
        greater_than_or_equal_to: -> { partitioning_strategy.retain_for.ago.to_date },
        less_than_or_equal_to: -> { (Date.current.end_of_month + partitioning_strategy.class::HEADROOM).end_of_month }
      }

    def self.buffer_usage(event)
      feature = FEATURES_BY_EVENT[event.event]
      usage = event.extras&.dig('usage')
      return unless feature && usage.is_a?(Hash)

      rows = usage.filter_map do |model, tokens|
        next unless tokens.is_a?(Hash)

        {
          organization_id: event.namespace&.organization_id || event.organization_id,
          traversal_ids: event.namespace&.traversal_ids || [],
          user_id: event.user_id,
          feature: feature,
          model: model,
          usage_date: event.timestamp.utc.to_date,
          input_tokens: tokens['input_tokens'],
          output_tokens: tokens['output_tokens'],
          events_count: 1,
          namespace_id: event.namespace_id,
          event: event.event,
          timestamp: event.timestamp
        }
      end

      write_buffer.add(rows) if rows.any?
    end

    def self.transfer_organization(relation, from:, to:)
      return if from == to

      batch_size = ::Organizations::Transfer::Concerns::OrganizationUpdater::ORGANIZATION_ID_UPDATE_BATCH_SIZE
      rows = where(organization_id: from).merge(relation)

      # Not each_batch: its first query orders by id, which walks every partition's primary key when no row matches.
      loop do
        keys = rows.limit(batch_size).pluck(:id, :usage_date)
        break if keys.empty?

        rows.where(id: keys.map(&:first), usage_date: keys.map(&:last).uniq).update_all(organization_id: to)
      end
    end
  end
end
