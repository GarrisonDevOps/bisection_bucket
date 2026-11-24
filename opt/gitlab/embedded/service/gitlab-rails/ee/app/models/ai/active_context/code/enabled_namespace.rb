# frozen_string_literal: true

module Ai
  module ActiveContext
    module Code
      class EnabledNamespace < ApplicationRecord
        include PartitionedTable

        PARTITION_SIZE = 2_000_000
        METADATA_SIZE_LIMIT = 64.kilobytes

        self.table_name = 'p_ai_active_context_code_enabled_namespaces'
        self.primary_key = :id

        # rubocop:disable Database/AvoidIntRangePartitioning -- legacy usage
        partitioned_by :namespace_id, strategy: :int_range, partition_size: PARTITION_SIZE
        # rubocop:enable Database/AvoidIntRangePartitioning

        belongs_to :namespace
        belongs_to :active_context_connection, class_name: 'Ai::ActiveContext::Connection',
          foreign_key: 'connection_id', inverse_of: :enabled_namespaces

        has_many :repositories,
          class_name: 'Ai::ActiveContext::Code::Repository', inverse_of: :enabled_namespace

        validates :namespace, presence: true
        validates :active_context_connection, presence: true
        validates :state, presence: true
        validates :connection_id, uniqueness: { scope: :namespace_id }
        validate :valid_namespace
        validates :metadata, json_schema: {
          filename: 'ai_active_context_code_enabled_namespaces_metadata',
          size_limit: METADATA_SIZE_LIMIT
        }

        enum :state, {
          pending: 0,
          ready: 10
        }

        scope :namespace_id_in, ->(namespace_ids) { where(namespace_id: namespace_ids) }
        scope :with_active_connection, -> {
          joins(:active_context_connection).where(active_context_connection: { active: true })
        }
        scope :ordered_by_id, -> { order(:id) }
        scope :id_greater_than, ->(id) { where('id > ?', id) }

        def self.valid_saas_namespaces
          Namespace
            .group_namespaces
            .top_level
            .with_ai_supported_plan(:semantic_code_search)
            .merge(GitlabSubscription.not_expired)
        end

        def self.find_enabled_namespace(connection, namespace)
          connection.enabled_namespaces.find_by(namespace: namespace)
        end

        private

        def valid_namespace
          return if namespace && namespace.root? && namespace.group_namespace?

          errors.add(:namespace, _('must be a root group.'))
        end
      end
    end
  end
end
