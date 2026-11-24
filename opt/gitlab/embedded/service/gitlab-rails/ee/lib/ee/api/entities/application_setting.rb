# frozen_string_literal: true

module EE
  module API
    module Entities
      module ApplicationSetting
        extend ActiveSupport::Concern

        prepended do
          expose(*EE::ApplicationSettingsHelper.repository_mirror_attributes, if: ->(_instance, _options) do
            ::License.feature_available?(:repository_mirrors)
          end)
          expose(*EE::ApplicationSettingsHelper.merge_request_appovers_rules_attributes, if: ->(_instance, _options) do
            ::License.feature_available?(:admin_merge_request_approvers_rules)
          end)
          expose(*EE::ApplicationSettingsHelper.password_complexity_attributes, if: ->(_instance, _options) do
            ::License.feature_available?(:password_complexity)
          end)
          expose :email_additional_text, if: ->(_instance, _opts) { ::License.feature_available?(:email_additional_text) }
          expose :file_template_project_id, if: ->(_instance, _opts) { ::License.feature_available?(:custom_file_templates) }
          expose :default_project_deletion_protection, if: ->(_instance, _opts) { ::License.feature_available?(:default_project_deletion_protection) }
          expose :disable_personal_access_tokens, if: ->(_instance, _opts) { ::License.feature_available?(:disable_personal_access_tokens) }
          expose :updating_name_disabled_for_users, if: ->(_instance, _opts) { ::License.feature_available?(:disable_name_update_for_users) }
          expose :maven_package_requests_forwarding, if: ->(_instance, _opts) { ::License.feature_available?(:package_forwarding) }
          expose :npm_package_requests_forwarding, if: ->(_instance, _opts) { ::License.feature_available?(:package_forwarding) }
          expose :virtual_registries_endpoints_api_limit, if: ->(_instance, _opts) { ::License.feature_available?(:packages_virtual_registry) }
          expose :audit_events_api_limit, if: ->(_instance, _opts) { ::License.feature_available?(:admin_audit_log) }
          expose :project_audit_events_api_limit, if: ->(_instance, _opts) { ::License.feature_available?(:audit_events) }
          expose :group_audit_events_api_limit, if: ->(_instance, _opts) { ::License.feature_available?(:audit_events) }
          expose :dependency_scanning_sbom_scan_api_upload_limit, if: ->(_instance, _opts) { ::License.feature_available?(:dependency_scanning) }
          expose :dependency_scanning_sbom_scan_api_download_limit, if: ->(_instance, _opts) { ::License.feature_available?(:dependency_scanning) }
          expose :secret_push_protection_available, if: ->(_instance, _opts) { ::License.feature_available?(:secret_push_protection) }
          expose :secret_push_protection_available,
            if: ->(_instance, _opts) { ::License.feature_available?(:secret_push_protection) },
            as: :pre_receive_secret_detection_enabled
          expose :pypi_package_requests_forwarding, if: ->(_instance, _opts) { ::License.feature_available?(:package_forwarding) }
          expose :rubygems_package_requests_forwarding, if: ->(_instance, _opts) { ::License.feature_available?(:package_forwarding) }
          expose :group_owners_can_manage_default_branch_protection, if: ->(_instance, _opts) { ::License.feature_available?(:default_branch_protection_restriction_in_groups) }
          expose :maintenance_mode, if: ->(_instance, _opts) { RegistrationFeatures::MaintenanceMode.feature_available? }
          expose :maintenance_mode_message, if: ->(_instance, _opts) { RegistrationFeatures::MaintenanceMode.feature_available? }
          expose :service_access_tokens_expiration_enforced
          expose :git_two_factor_session_expiry, if: ->(_instance, _opts) { License.feature_available?(:git_two_factor_enforcement) && ::Feature.enabled?(:two_factor_for_cli) }
          expose(*EE::ApplicationSettingsHelper.git_abuse_rate_limit_attributes, if: ->(_instance, _options) do
            ::License.feature_available?(:git_abuse_rate_limit)
          end)
          expose(*EE::ApplicationSettingsHelper.delete_unconfirmed_users_attributes, if: ->(_instance, _options) do
            ::License.feature_available?(:delete_unconfirmed_users)
          end)
          expose :make_profile_private, if: ->(_instance, _opts) do
            ::License.feature_available?(:disable_private_profiles)
          end
          expose :duo_custom_agents_enabled, documentation: { type: 'Boolean' }, if: ->(_instance, _opts) { ::License.ai_features_available? }
          expose :lock_duo_custom_agents_enabled, documentation: { type: 'Boolean' }, if: ->(_instance, _opts) { ::License.ai_features_available? }
          expose :duo_custom_flows_enabled, documentation: { type: 'Boolean' }, if: ->(_instance, _opts) { ::License.ai_features_available? }
          expose :lock_duo_custom_flows_enabled, documentation: { type: 'Boolean' }, if: ->(_instance, _opts) { ::License.ai_features_available? }
          expose :duo_external_agents_enabled, documentation: { type: 'Boolean' }, if: ->(_instance, _opts) { ::License.ai_features_available? }
          expose :lock_duo_external_agents_enabled, documentation: { type: 'Boolean' }, if: ->(_instance, _opts) { ::License.ai_features_available? }
          expose :duo_features_enabled, if: ->(_instance, _opts) { ::License.ai_features_available? }
          expose :duo_agent_platform_enabled, if: ->(_instance, _opts) { ::License.ai_features_available? } do |_instance|
            ai_settings.duo_agent_platform_enabled
          end
          expose :duo_cli_enabled,
            if: ->(_instance, _opts) { ::License.ai_features_available? } do |_instance|
            ai_settings.duo_cli_enabled
          end
          expose :ai_audit_events_streaming_enabled,
            documentation: { type: 'Boolean' },
            if: ->(_instance, _opts) { ::License.ai_features_available? } do |_instance|
            ai_settings.ai_audit_events_streaming_enabled
          end
          expose :duo_token_usage_tracking_enabled,
            documentation: { type: 'Boolean' },
            if: ->(_instance, _opts) { ::License.ai_features_available? } do |_instance|
            ai_settings.duo_token_usage_tracking_enabled
          end
          expose :duo_workflow_file_attachments_enabled,
            documentation: { type: 'Boolean' },
            if: ->(_instance, _opts) { ::License.ai_features_available? } do |_instance|
            ai_settings.duo_workflow_file_attachments_enabled
          end
          expose :lock_duo_features_enabled, if: ->(_instance, _opts) { ::License.ai_features_available? }
          expose :enabled_expanded_logging, if: ->(_instance, _opts) { ::License.ai_features_available? }
          expose :foundational_agents_default_enabled, if: ->(_instance, _opts) { ::License.ai_features_available? }
          expose :foundational_agents_statuses, if: ->(_instance, _opts) { ::License.ai_features_available? }
          expose :duo_workflows_default_image_registry, if: ->(_instance, _opts) { ::License.ai_features_available? }
          expose :duo_template_project_id, if: ->(instance, _opts) { instance.duo_template_project_available? }
          expose :ci_telemetry_otel_endpoint, if: ->(_instance, _opts) { ::Feature.enabled?(:ci_job_telemetry_settings, :instance, type: :experiment) }
          expose :ci_job_telemetry_sampling_rate, if: ->(_instance, _opts) { ::Feature.enabled?(:ci_job_telemetry_settings, :instance, type: :experiment) }
          expose :disabled_direct_code_suggestions, if: ->(_instance, _opts) { ::GitlabSubscriptions::AddOnPurchase.exists_for_unit_primitive?(:complete_code, :instance) }
          expose :allow_top_level_group_owners_to_create_service_accounts
          expose :use_nats_for_audit_streaming, documentation: { type: 'Boolean' }
          expose :auto_duo_code_review_enabled,
            if: ->(instance, _opts) {
              ::Gitlab::Duo::CodeReview.automatic_review_available?(instance)
            }
          expose :duo_code_review_decisions_enabled,
            if: ->(instance, _opts) {
              ::Gitlab::Duo::CodeReview.decisions_settings_available?(instance)
            }
          with_options if: ->(instance, _opts) { ::Gitlab::Duo::CodeReview.depth_settings_available?(instance) } do
            expose :duo_code_review_depth_allowed, documentation: { type: 'Boolean' }
            expose :duo_code_review_default_depth, documentation: { type: 'String', example: 'lite' }
          end
          expose :elasticsearch_index_settings,
            using: ::API::Entities::Elastic::IndexSetting,
            documentation: { is_array: true, desc: 'Elasticsearch index settings.' },
            if: ->(_instance, _opts) { ::License.feature_available?(:elastic_search) }
          expose :duo_namespace_access_rules, if: ->(_instance, _opts) { ::License.ai_features_available? } do |instance|
            feature_access_rules(instance.duo_namespace_access_rules)
          end
          expose :built_in_project_templates_enabled,
            documentation: { type: 'Boolean' },
            if: ->(instance, _opts) { instance.instance_built_in_project_templates_enabled_available? }
          expose :lock_built_in_project_templates_enabled,
            documentation: { type: 'Boolean' },
            if: ->(instance, _opts) { instance.instance_built_in_project_templates_enabled_available? }
          private

          def ai_settings
            ::Ai::Setting.for_current_or_default_organization
          end

          def feature_access_rules(rules)
            ::Ai::FeatureAccessRuleTransformer.transform(rules)
          end
        end
      end
    end
  end
end
