# frozen_string_literal: true

module EE
  module ProjectSetting
    extend ActiveSupport::Concern

    extend ::Gitlab::Utils::Override

    prepended do
      include Security::PipelineExecutionPolicyCiConfigAccess
      include ::Ai::CodeReview::DepthSettings

      cascading_attr :duo_features_enabled, :spp_repository_pipeline_access, :model_prompt_cache_enabled,
        :auto_duo_code_review_enabled, :duo_remote_flows_enabled, :duo_foundational_flows_enabled,
        :duo_scheduled_triggers_enabled,
        :tool_approval_for_session_enabled, :ai_audit_events_storage_enabled,
        :auto_duo_code_review_on_push_enabled, :duo_auto_mode_enabled,
        :duo_code_review_decisions_enabled, :duo_code_review_approval_counts_enabled, :ai_governance_enabled,
        :ai_agent_governance_enforcement

      belongs_to :push_rule
      belongs_to :duo_dependency_bump_breaking_changes_enabled_by, class_name: 'User', optional: true

      scope :has_vulnerabilities, -> { where('has_vulnerabilities IS TRUE') }
      scope :with_duo_sast_fp_detection_enabled, -> { where('duo_sast_fp_detection_enabled IS TRUE') }
      scope :with_duo_sast_vr_workflow_enabled, -> { where('duo_sast_vr_workflow_enabled IS TRUE') }
      scope :with_duo_vulnerability_context_analysis_enabled,
        -> { where('duo_vulnerability_context_analysis_enabled IS TRUE') }
      scope :duo_features_set, ->(setting) { where(duo_features_enabled: setting) }

      validates :ai_agent_governance_enforcement,
        numericality: { only_integer: true },
        inclusion: { in: ::Ai::Governance::AgentCredentialEnforcement::MODES.values },
        'ai/governance/enforcement_mode_input': true,
        if: :will_save_change_to_ai_agent_governance_enforcement?
      validates :mirror_branch_regex, absence: true, if: -> { project&.only_mirror_protected_branches? }
      validates :mirror_branch_regex, untrusted_regexp: true, length: { maximum: 255 }
      validates :product_analytics_instrumentation_key, length: { maximum: 255 }, allow_blank: true
      validates :product_analytics_configurator_connection_string,
        length: { maximum: 512 },
        addressable_url: { schemes: %w[http https], allow_localhost: true, allow_local_network: true },
        allow_blank: true
      validates :product_analytics_data_collector_host,
        length: { maximum: 255 },
        addressable_url: { schemes: %w[http https], allow_localhost: true, allow_local_network: true },
        allow_blank: true
      validates :cube_api_base_url,
        length: { maximum: 512 },
        addressable_url: { schemes: %w[http https], allow_localhost: true, allow_local_network: true },
        allow_blank: true
      validates :cube_api_key, length: { maximum: 255 }, allow_blank: true
      validates :duo_context_exclusion_settings,
        json_schema: {
          filename: 'duo_context_exclusion_settings',
          size_limit: -> {
            64.kilobytes if ::Feature.enabled?(:duo_context_exclusion_settings_size_limit, :instance)
          }
        },
        if: :will_save_change_to_duo_context_exclusion_settings?

      validates :observability_alerts_enabled, inclusion: { in: [true, false] }

      validate :presence_of_merge_request_title_regex_settings,
        if: -> {
          project &&
            project.licensed_feature_available?(:merge_request_title_regex_check)
        }

      after_update :enqueue_auto_merge_workers,
        if: -> {
          project &&
            project.licensed_feature_available?(:merge_request_title_regex_check) &&
            saved_change_to_merge_request_title_regex
        }

      validate :all_or_none_product_analytics_attributes_set

      attribute :enabled_foundational_flows, :integer, array: true, default: nil

      def all_or_none_product_analytics_attributes_set
        attrs = [
          :encrypted_product_analytics_configurator_connection_string,
          :product_analytics_data_collector_host,
          :cube_api_base_url,
          :encrypted_cube_api_key
        ]

        return if attrs.all? { |attr| self[attr].present? } || attrs.all? { |attr| self[attr].blank? }

        errors.add(:data_sources_settings, 'must all be set or none should be set')
      end
    end

    def selective_code_owner_removals
      project.licensed_feature_available?(:merge_request_approvers) &&
        ComplianceManagement::MergeRequestApprovalSettings::Resolver
        .new(project.group, project: project)
        .selective_code_owner_removals
        .value
    end

    def has_confluence?
      super && !::Integrations::Confluence.blocked_by_settings?(log: true)
    end

    override :reviewer_auto_assignment_available?
    def reviewer_auto_assignment_available?
      project.licensed_feature_available?(:code_owners)
    end

    def dap_session_tracking_available?
      ::Feature.enabled?(:dap_session_commit_tracking, project) &&
        project.licensed_feature_available?(:ai_workflows) &&
        project.duo_features_enabled
    end

    def dap_session_tracking_enabled?
      dap_session_tracking_available? && dap_session_tracking_enabled
    end

    def mark_as_vulnerable!
      return if has_vulnerabilities?

      update!(has_vulnerabilities: true)
    end
  end
end
