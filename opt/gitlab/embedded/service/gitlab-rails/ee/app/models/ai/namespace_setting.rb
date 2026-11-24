# frozen_string_literal: true

module Ai
  class NamespaceSetting < ApplicationRecord
    self.table_name = "namespace_ai_settings"

    include HasRolePermissions
    include NormalizesDomainLists

    # Settings whose explicit submission is recorded in `configured_at` (key presence = explicitly configured).
    PROVENANCE_TRACKED_SETTINGS = %w[
      duo_workflow_mcp_enabled
      ai_usage_data_collection_enabled
      ai_catalog_restricted_to_group_hierarchy
      web_search_enabled
      prompt_injection_protection_level
      duo_workflow_file_attachments_enabled
    ].freeze

    # Settings that only top-level groups may change.
    TOP_LEVEL_GROUP_SETTINGS = %w[
      ai_catalog_restricted_to_group_hierarchy
      web_search_enabled
      duo_workflow_file_attachments_enabled
    ].freeze

    enum :prompt_injection_protection_level, {
      log_only: 0,
      no_checks: 1,
      interrupt: 2
    }

    jsonb_accessor :feature_settings,
      duo_agent_platform_enabled: [:boolean, { default: true }]

    validates :feature_settings,
      json_schema: { filename: "ai_namespace_setting_feature_settings", size_limit: 64.kilobytes }

    validates :configured_at,
      json_schema: { filename: "ai_namespace_setting_configured_at", size_limit: 64.kilobytes }

    validates :duo_workflow_mcp_enabled, inclusion: { in: [true, false] }
    validates :prompt_injection_protection_level, presence: true
    validates :ai_usage_data_collection_enabled, inclusion: { in: [true, false] }
    validates :ai_catalog_restricted_to_group_hierarchy, inclusion: { in: [true, false] }
    validates :web_search_enabled, inclusion: { in: [true, false] }
    validates :duo_workflow_file_attachments_enabled, inclusion: { in: [true, false] }
    validate :validate_top_level_group_settings

    belongs_to :namespace, inverse_of: :ai_settings

    # Top-level groups with the Foundational agents switch off (or never set: the column is nullable and
    # NULL acts as off) that still run an agent they turned on explicitly. Once the switch gates every
    # agent they would lose it; see ReconcileStatusesService.
    scope :with_foundational_agents_switch_off_and_agent_on, -> do
      joins(:namespace)
        .merge(::Group.top_level)
        .where(foundational_agents_default_enabled: [false, nil])
        .where_exists(
          ::Ai::NamespaceFoundationalAgentStatus.enabled
            .where('namespace_foundational_agent_statuses.namespace_id = namespace_ai_settings.namespace_id')
        )
    end
    scope :preload_namespace_and_foundational_agent_statuses, -> do
      preload(namespace: :foundational_agents_status_records)
    end

    private

    def validate_top_level_group_settings
      changed_settings = changed & TOP_LEVEL_GROUP_SETTINGS
      return if changed_settings.empty? || top_level_group_namespace?

      changed_settings.each { |setting| errors.add(setting, _('can only be set for top-level groups')) }
    end

    def top_level_group_namespace?
      namespace&.root? && namespace.group_namespace?
    end
  end
end
