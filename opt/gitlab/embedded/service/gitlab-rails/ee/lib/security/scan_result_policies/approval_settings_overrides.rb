# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class ApprovalSettingsOverrides
      include Gitlab::Utils::StrongMemoize

      Override = Data.define(:attribute, :security_policies)

      def initialize(project:, warn_mode_policies:, enforced_policies:)
        @project = project
        @warn_mode_policies = warn_mode_policies
        @enforced_policies = enforced_policies
        @warn_mode_settings_index = {}

        index_warn_mode_policies!
      end

      def all
        project_settings.filter_map do |attr, val|
          # If the project setting is restrictive, it can't be overridden.
          next if val

          # Does a warn-mode policy override the attribute?
          next unless warn_mode_approval_settings[attr]

          # Does an enforced policy already set the attribute?
          next if enforced_approval_settings[attr]

          Override.new(attr, warn_mode_settings_index.fetch(attr))
        end
      end

      private

      attr_reader :project,
        :warn_mode_policies,
        :enforced_policies,
        :warn_mode_settings_index

      def project_settings
        settings = {
          prevent_approval_by_author: !project.merge_requests_author_approval?,
          prevent_approval_by_commit_author: project.merge_requests_disable_committers_approval?,
          remove_approvals_with_new_commit: project.reset_approvals_on_push?,
          # Policy settings resolve to the most secure option when they conflict with the
          # project's, so a project removing all approvals is not overridden by this narrower
          # removal - ResetApprovalsService never reaches the selective branch there, and
          # reporting an override would claim an enforcement that does not happen.
          # See https://gitlab.com/groups/gitlab-org/-/epics/9696.
          remove_code_owner_approvals_with_new_commit: project.project_setting.selective_code_owner_removals ||
            project.reset_approvals_on_push?,
          require_password_to_approve: project.require_password_to_approve?,
          prevent_editing_approval_rules: project.disable_overriding_approvers_per_merge_request?
        }

        # The setting is inert while the flag is off, so it must not be reported as an
        # override - that would claim an enforcement the service layer does not apply.
        unless ::Feature.enabled?(:approval_policy_selective_code_owner_removals, project)
          settings.delete(:remove_code_owner_approvals_with_new_commit)
        end

        settings
      end

      def warn_mode_approval_settings
        aggregate_approval_settings(warn_mode_policies)
      end
      strong_memoize_attr :warn_mode_approval_settings

      def enforced_approval_settings
        aggregate_approval_settings(enforced_policies)
      end
      strong_memoize_attr :enforced_approval_settings

      def aggregate_approval_settings(policies)
        policies.reduce({}) do |acc, policy|
          settings = approval_settings(policy)

          next acc unless settings.present?

          # If there are multiple policies with a conflicting property,
          # eg. {true, false}, then the aggregate property is determined by
          # logical OR, so that more restrictive policies take precedence.
          acc.merge(settings) { |_key, old_val, new_val| old_val || new_val }
        end
      end

      def approval_settings(policy)
        policy
          .content
          .fetch("approval_settings", {})
          .symbolize_keys
      end

      def index_warn_mode_policies!
        warn_mode_policies.each do |policy|
          approval_settings(policy).each do |(attr, val)|
            next unless val # permissive?

            (warn_mode_settings_index[attr] ||= Set.new) << policy
          end
        end
      end
    end
  end
end
