# frozen_string_literal: true

module EE
  module API
    module Entities
      module GroupDetail
        extend ActiveSupport::Concern

        prepended do
          expose :shared_runners_minutes_limit
          expose :extra_shared_runners_minutes_limit
          expose :prevent_forking_outside_group?, as: :prevent_forking_outside_group
          expose :service_access_tokens_expiration_enforced?, as: :service_access_tokens_expiration_enforced,
            if: ->(group, options) { group.root? }

          expose :experiment_features_enabled,
            documentation: {
              type: 'Boolean',
              desc: 'If `true`, experimental and beta AI features are enabled for the group. Premium and Ultimate only.'
            },
            if: ->(group, options) {
              options[:current_user].present? &&
                group.licensed_ai_features_available? &&
                Ability.allowed?(options[:current_user], :read_group, group)
            } do |group, options|
              if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
                options[:current_user].governing_namespace(group)&.experiment_features_enabled || false
              else
                ::Gitlab::CurrentSettings.instance_level_ai_beta_features_enabled?
              end
            end

          expose :ai_settings,
            using: ::API::Entities::AiSettings,
            documentation: {
              type: '::API::Entities::AiSettings',
              desc: 'AI-related settings for the group. Returned only to users who can read the group, when AI ' \
                'features are available for the group.'
            },
            if: ->(group, options) {
              options[:current_user].present? &&
                group.licensed_ai_features_available? &&
                Ability.allowed?(options[:current_user], :read_group, group)
            } do |group| # rubocop:disable Style/SymbolProc -- Grape block exposure requires an explicit block argument
            group.ai_settings
          end

          can_admin_duo_remote_flows = ->(group, options) {
            group.licensed_feature_available?(:ai_workflows) &&
              Ability.allowed?(options[:current_user], :admin_group, group)
          }

          expose :duo_remote_flows_enabled,
            if: can_admin_duo_remote_flows,
            documentation: { type: 'Boolean' }
          expose :lock_duo_remote_flows_enabled,
            if: can_admin_duo_remote_flows,
            documentation: { type: 'Boolean' } do |group|
            group.namespace_settings&.duo_remote_flows_enabled_locked?(include_self: true)
          end

          expose :membership_lock?, as: :membership_lock
          expose :ip_restriction_ranges,
            if: ->(group, options) { group.licensed_feature_available?(:group_ip_restriction) }

          expose :allowed_email_domains_list,
            if: ->(group, options) { group.licensed_feature_available?(:group_allowed_email_domains) }

          expose :only_allow_merge_if_pipeline_succeeds,
            if: ->(group, options) { group.licensed_feature_available?(:group_level_merge_checks_setting) } do |group|
            group.namespace_settings&.only_allow_merge_if_pipeline_succeeds
          end

          expose :allow_merge_on_skipped_pipeline,
            if: ->(group, options) { group.licensed_feature_available?(:group_level_merge_checks_setting) } do |group|
            group.namespace_settings&.allow_merge_on_skipped_pipeline
          end

          expose :only_allow_merge_if_all_discussions_are_resolved,
            if: ->(group, options) { group.licensed_feature_available?(:group_level_merge_checks_setting) } do |group|
            group.namespace_settings&.only_allow_merge_if_all_discussions_are_resolved
          end

          unique_project_download_limit_enabled = ->(group, options) do
            Ability.allowed?(options[:current_user], :admin_group, group) &&
              group.namespace_settings.present? &&
              group.unique_project_download_limit_enabled?
          end
          expose :unique_project_download_limit, if: unique_project_download_limit_enabled
          expose :unique_project_download_limit_interval_in_seconds, if: unique_project_download_limit_enabled
          expose :unique_project_download_limit_allowlist, if: unique_project_download_limit_enabled
          expose :unique_project_download_limit_alertlist, if: unique_project_download_limit_enabled
          expose :auto_ban_user_on_excessive_projects_download, if: unique_project_download_limit_enabled

          private

          def unique_project_download_limit
            settings&.unique_project_download_limit
          end

          def unique_project_download_limit_interval_in_seconds
            settings&.unique_project_download_limit_interval_in_seconds
          end

          def unique_project_download_limit_allowlist
            settings&.unique_project_download_limit_allowlist
          end

          def unique_project_download_limit_alertlist
            settings&.unique_project_download_limit_alertlist
          end

          def auto_ban_user_on_excessive_projects_download
            settings&.auto_ban_user_on_excessive_projects_download
          end

          def settings
            object&.namespace_settings
          end
        end
      end
    end
  end
end
