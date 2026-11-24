# frozen_string_literal: true

module EE
  module API
    module Helpers
      module GroupsHelpers
        extend ActiveSupport::Concern

        AI_MINIMUM_ACCESS_LEVEL_EXECUTE_ALLOWED_VALUES = [
          ::Gitlab::Access::GUEST,
          ::Gitlab::Access::PLANNER,
          ::Gitlab::Access::REPORTER,
          ::Gitlab::Access::DEVELOPER,
          ::Gitlab::Access::MAINTAINER,
          ::Gitlab::Access::OWNER
        ].freeze

        AI_MINIMUM_ACCESS_LEVEL_ALLOWED_VALUES = [
          ::Gitlab::Access::DEVELOPER,
          ::Gitlab::Access::MAINTAINER,
          ::Gitlab::Access::OWNER
        ].freeze

        prepended do
          params :optional_params_ee do
            optional :membership_lock, type: ::Grape::API::Boolean, desc: 'Prevent adding new members to projects within this group. Premium and Ultimate only.'
            optional :ldap_cn, type: String, desc: 'LDAP Common Name'
            optional :ldap_access, type: Integer, desc: 'A valid access level'
            optional :shared_runners_minutes_limit, type: Integer, desc: '(admin-only) Maximum number of monthly compute minutes for this group. `nil` (default) inherits the instance default, and `0` means unlimited. GitLab Self-Managed, Premium and Ultimate only.'
            optional :extra_shared_runners_minutes_limit, type: Integer, desc: '(admin-only) Extra compute minutes quota for this group. GitLab Self-Managed, Premium and Ultimate only.'
            optional :wiki_access_level, type: String, values: %w[disabled private enabled], desc: 'Wiki access level. One of `disabled`, `private` or `enabled`. Premium and Ultimate only.'
            optional :duo_availability, type: String, values: ::EE::NamespaceSetting::DUO_AVAILABILITY_VALUES, desc: 'Duo availability. One of `default_on`, `default_off`, `never_on` or `always_on`. In the UI, `never_on` is displayed as Always Off.'
            optional :duo_remote_flows_availability, type: ::Grape::API::Boolean, desc: 'Enable GitLab Duo remote flows for this group'
            optional :duo_foundational_flows_availability, type: ::Grape::API::Boolean, desc: 'Enable GitLab foundational Duo flows for this group'
            optional :duo_scheduled_automations_availability, as: :duo_scheduled_triggers_availability,
              type: ::Grape::API::Boolean, desc: 'Allow GitLab Duo flows in this group to run on a schedule'
            optional :duo_custom_agents_availability, type: ::Grape::API::Boolean, desc: 'Enable GitLab Duo custom agents for this group'
            optional :duo_custom_flows_availability, type: ::Grape::API::Boolean, desc: 'Enable GitLab Duo custom flows for this group'
            optional :duo_external_agents_availability, type: ::Grape::API::Boolean, desc: 'Enable GitLab Duo external agents for this group'
            optional :tool_approval_for_session_availability, type: String, values: %w[default_on default_off never_on], desc: 'Tool approval for session availability. One of `default_on`, `default_off` or `never_on`'
            optional :duo_auto_mode_availability, type: String, values: %w[default_on default_off never_on], desc: 'Duo auto mode availability. One of `default_on`, `default_off` or `never_on`'
            optional :amazon_q_auto_review_enabled, type: ::Grape::API::Boolean, desc: 'Enable Amazon Q auto review for merge request'
            optional :experiment_features_enabled, type: ::Grape::API::Boolean, desc: 'Enable experiment features for this group'
            optional :model_prompt_cache_enabled, type: ::Grape::API::Boolean, desc: 'Enable model prompt cache for this group'
            optional :foundational_agents_statuses, type: Array, desc: 'Whether each foundational agent has been enabled or disabled.' do
              requires :reference, type: String, desc: 'Reference of the foundational agent.'
              requires :enabled, type: ::Grape::API::Boolean, desc: 'Whether foundational agent has been enabled or disabled.'
            end
            optional :ai_settings_attributes, type: Hash, desc: 'AI-related settings' do
              optional :duo_agent_platform_enabled, type: ::Grape::API::Boolean, desc: 'Whether Duo Agent Platform features are enabled'
              optional :duo_workflow_mcp_enabled, type: ::Grape::API::Boolean, desc: 'Enable MCP support for Duo Agent Platform'
              optional :ai_usage_data_collection_enabled, type: ::Grape::API::Boolean, desc: 'Enable AI usage data collection for this namespace. GitLab.com only.'
              optional :ai_catalog_restricted_to_group_hierarchy, type: ::Grape::API::Boolean, desc: 'Confine the AI Catalog to items within this top-level group hierarchy. Can only be set on top-level groups.'
              optional :web_search_enabled, type: ::Grape::API::Boolean, desc: 'Allow web search in GitLab Duo Chat for this top-level group. Can only be set on top-level groups.'
              optional :duo_workflow_file_attachments_enabled, type: ::Grape::API::Boolean, desc: 'Allow file attachments in GitLab Duo Chat for this top-level group. Can only be set on top-level groups. GitLab.com only.'
              optional :foundational_agents_default_enabled, type: ::Grape::API::Boolean, desc: 'Whether new foundational agents are enabled by default'
              optional :prompt_injection_protection_level, type: String, values: %w[no_checks log_only interrupt], desc: 'Prompt injection protection level. One of `no_checks`, `log_only` or `interrupt`'
              optional :include_recommended_allowed, type: ::Grape::API::Boolean, desc: 'Whether to include recommended domains in the network access allowlist'
              optional :allow_all_unix_sockets, type: ::Grape::API::Boolean, desc: 'Whether to allow all Unix sockets for network access'
              optional :allow_project_extension, type: ::Grape::API::Boolean, desc: 'Whether to allow projects to extend the network access domain allowlist'
              optional :require_sandbox, type: ::Grape::API::Boolean, desc: 'Whether flows that run on GitLab Runner fail when the execution environment sandbox is unavailable. Applies only to top-level groups on GitLab.com.'
              # rubocop:disable API/AccessLevelStringType -- Introduced before the cop
              optional :minimum_access_level_execute, type: Integer, values: AI_MINIMUM_ACCESS_LEVEL_EXECUTE_ALLOWED_VALUES, desc: 'The minimum access level required to execute Duo Agent Platform. Behind a feature flag named `dap_group_customizable_permissions`, disabled by default.'
              optional :minimum_access_level_execute_async, type: Integer, values: AI_MINIMUM_ACCESS_LEVEL_ALLOWED_VALUES, desc: 'The minimum access level required to execute Duo Agent Platform features in CI/CD. Behind a feature flag named `dap_group_customizable_permissions`, disabled by default.'
              optional :minimum_access_level_manage, type: Integer, values: AI_MINIMUM_ACCESS_LEVEL_ALLOWED_VALUES, desc: 'The minimum access level required to manage Duo Agent Platform. Behind a feature flag named `dap_group_customizable_permissions`, disabled by default.'
              optional :minimum_access_level_enable_on_projects, type: Integer, values: AI_MINIMUM_ACCESS_LEVEL_ALLOWED_VALUES, desc: 'The minimum access level required to enable Duo Agent Platform. Behind a feature flag named `dap_group_customizable_permissions`, disabled by default.'
              # rubocop:enable API/AccessLevelStringType
            end
            all_or_none_of :ldap_cn, :ldap_access
          end

          params :optional_update_params_ee do
            optional :file_template_project_id,
              type: Integer, desc: 'The ID of a project to use for custom templates in this group. Premium and Ultimate only.'
            optional :prevent_forking_outside_group,
              type: ::Grape::API::Boolean, desc: 'Prevent forking projects inside this group to external namespaces. Premium and Ultimate only.'
            optional :unique_project_download_limit,
              type: Integer,
              desc: 'Maximum number of unique projects a user can download in the specified time period before they ' \
                    'are banned. Available only on top-level groups. Default is `0`. Maximum is `10000`. Ultimate only.'
            optional :unique_project_download_limit_interval_in_seconds,
              type: Integer,
              desc: 'Time period, in seconds, during which a user can download a maximum amount of projects before they are banned. ' \
                    'Available only on top-level groups. Default is `0`. Maximum is `864000` (10 days). Ultimate only.'
            optional :unique_project_download_limit_allowlist,
              type: Array[String],
              coerce_with: ::API::Validations::Types::CommaSeparatedToArray.coerce,
              desc: 'List of usernames excluded from the unique project download limit. Available only on top-level groups. Maximum of 100 usernames. Ultimate only.'
            optional :unique_project_download_limit_alertlist,
              type: Array[Integer],
              desc: 'List of user ids who will be emailed when Git abuse rate limit is exceeded. Available only on top-level groups. Maximum of 100 user IDs. When empty, the active Owners of the group are emailed. Ultimate only.'
            optional :auto_ban_user_on_excessive_projects_download,
              type: Grape::API::Boolean,
              desc: 'Ban users from the group when they exceed maximum number of unique projects download in the specified time period, as set by `unique_project_download_limit` and `unique_project_download_limit_interval_in_seconds`. Available only on top-level groups. Ultimate only.'
            optional :ip_restriction_ranges,
              type: String,
              desc: 'Comma-separated list of IP addresses or subnet masks to restrict group access. Premium and Ultimate only.'
            optional :allowed_email_domains_list,
              type: String,
              desc: 'Comma-separated list of email address domains to allow group access. Premium and Ultimate only. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/issues/351494) in GitLab 17.4.'
            optional :service_access_tokens_expiration_enforced,
              type: ::Grape::API::Boolean,
              desc: "To enforce token expiration for Service accounts users for group"
            optional :duo_core_features_enabled,
              type: ::Grape::API::Boolean,
              desc: '[Experimental] Indicates whether GitLab Duo Core features are enabled for the group'
            optional :duo_features_enabled,
              type: ::Grape::API::Boolean,
              desc: "Indicates whether GitLab Duo features are enabled for the group. GitLab Self-Managed, Premium and Ultimate only."
            optional :lock_duo_features_enabled,
              type: ::Grape::API::Boolean,
              desc: "Indicates if the GitLab Duo features enabled setting is enforced for all subgroups. GitLab Self-Managed, Premium and Ultimate only."
            optional :auto_duo_code_review_enabled,
              type: ::Grape::API::Boolean,
              desc: "Enable automatic reviews by GitLab Duo on merge requests"
            optional :duo_code_review_decisions_enabled,
              type: ::Grape::API::Boolean,
              desc: "Enable approval and change requests by GitLab Duo on merge requests"
            optional :duo_code_review_depth_allowed,
              type: ::Grape::API::Boolean,
              desc: "[Beta] Allow Standard reviews by GitLab Duo Code Review Flow"
            optional :duo_code_review_default_depth,
              type: String,
              values: ::Gitlab::Duo::CodeReview::DEPTHS,
              desc: "[Beta] Default review depth for GitLab Duo Code Review Flow. One of `lite` or `standard`"
            optional :ai_audit_events_storage_enabled,
              type: ::Grape::API::Boolean,
              desc: 'Indicates whether AI audit events are stored for the group. Premium and Ultimate only. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/245843) in GitLab 19.2.'
            optional :lock_ai_audit_events_storage_enabled,
              type: ::Grape::API::Boolean,
              desc: 'Indicates whether AI audit events storage is enforced for all subgroups and projects. Premium and Ultimate only. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/245843) in GitLab 19.2.'
            optional :ai_governance_enabled,
              type: ::Grape::API::Boolean,
              desc: 'Indicates whether AI Governance is turned on for the group, its subgroups, and its projects. Default is `false`. Premium and Ultimate only. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/261994) in GitLab 19.6.'
            optional :lock_ai_governance_enabled,
              type: ::Grape::API::Boolean,
              desc: 'Indicates whether the AI Governance setting is enforced for all subgroups and projects. Premium and Ultimate only. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/261994) in GitLab 19.6.'
            optional :web_based_commit_signing_enabled,
              type: ::Grape::API::Boolean,
              desc: 'Enable web based commit signing for commits created from the GitLab UI. When enabled for a group, applies to all projects in the group. GitLab.com only. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/193928) in GitLab 18.2.'
            optional :only_allow_merge_if_pipeline_succeeds,
              type: ::Grape::API::Boolean,
              desc: 'Only allow to merge if builds succeed. When enabled for a group, applies to all projects in the group. Premium and Ultimate only.'
            optional :allow_merge_on_skipped_pipeline,
              type: ::Grape::API::Boolean,
              desc: 'Allow to merge if pipeline is skipped. Can be `true` only when `only_allow_merge_if_pipeline_succeeds` is `true`. Premium and Ultimate only.'
            optional :only_allow_merge_if_all_discussions_are_resolved,
              type: ::Grape::API::Boolean,
              desc: 'Only allow to merge if all threads are resolved. When enabled for a group, applies to all projects in the group. Premium and Ultimate only.'
            optional :enabled_foundational_flows,
              type: Array[String], desc: 'References of enabled foundational flows'
            optional :duo_template_project_id,
              type: Integer,
              desc: 'The ID of a project to use as the Duo Code Review custom instructions template for this group'
            optional :allow_personal_snippets,
              type: ::Grape::API::Boolean,
              desc: 'Allow creation of personal snippets for enterprise users of this group. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/200575) in GitLab 18.5.'
            optional :duo_namespace_access_rules, type: Array, desc: 'AI entity access rules for controlling Duo feature access' do
              optional :through_namespace, type: Hash, desc: 'Object containing through namespace information' do
                requires :id, type: Integer, desc: 'ID of the through namespace'
                optional :name, type: String, desc: 'Name of the through namespace'
                optional :full_path, type: String, desc: 'Full path of the through namespace'
              end
              requires :features, type: Array[String], desc: 'List of accessible features', allow_blank: true
            end
            optional :built_in_project_templates_enabled,
              type: ::Grape::API::Boolean,
              desc: 'Enable built-in project templates for project creation. Premium and Ultimate only. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/235504) in GitLab 19.0.'
            optional :lock_built_in_project_templates_enabled,
              type: ::Grape::API::Boolean,
              desc: 'Enforce the built-in project templates setting for all subgroups. Premium and Ultimate only. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/235504) in GitLab 19.0.'
            optional :create_code_review_flow_consent,
              type: ::Grape::API::Boolean,
              desc: 'When true, records explicit namespace consent for DAP-based Code Review routing'
          end

          params :optional_projects_params_ee do
            optional :with_security_reports, type: ::Grape::API::Boolean, default: false, desc: 'If `true`, returns only projects that have security report artifacts present in any of their builds. Ultimate only.'
          end

          params :optional_group_list_params_ee do
            optional :repository_storage, type: String, desc: 'Filter by repository storage used by the group. Administrators only. Premium and Ultimate only.'
          end
        end
      end
    end
  end
end
