# frozen_string_literal: true

module EE
  module BasePolicy
    extend ActiveSupport::Concern

    prepended do
      with_scope :user
      condition(:auditor, score: 0) do
        # We pass in Gitlab::Auth::GroupSaml::TokenActor to policies via
        # Groups::SsoController#check_user_can_sign_in_with_provider.
        # However, only User can be an auditor.
        @user.respond_to?(:auditor?) && @user.auditor?
      end

      with_scope :user
      condition(:visual_review_bot, score: 0) { @user&.visual_review_bot? }

      with_scope :global
      condition(:license_block) { License.block_changes? }

      desc "User is security policy bot"
      with_options scope: :user, score: 0
      condition(:security_policy_bot) { @user&.security_policy_bot? }

      # rubocop:disable Gitlab/Authz/EnableInBasePolicy -- As of Feb 2026, we do not allow enables in base policy
      rule { auditor }.enable :read_all_resources
      # rubocop:enable Gitlab/Authz/EnableInBasePolicy

      condition(:locked_approval_rules, scope: :global) do
        License.feature_available?(:admin_merge_request_approvers_rules) &&
          ::Gitlab::CurrentSettings.disable_overriding_approvers_per_merge_request
      end

      with_scope :global
      condition(:allow_to_manage_default_branch_protection) do
        # When un-licensed: Always allow access.
        # When licensed: Allow or deny access based on the
        # `group_owners_can_manage_default_branch_protection` setting.
        !License.feature_available?(:default_branch_protection_restriction_in_groups) ||
          ::Gitlab::CurrentSettings.group_owners_can_manage_default_branch_protection
      end

      # token_info is set when authenticating user with a token. ai_workflows scope is used only by requests sent by Duo
      # Workflow.This is a temporary solution until https://gitlab.com/gitlab-org/gitlab/-/issues/468370 is done.
      with_scope :user
      condition(:duo_workflow_token, score: 0) do
        ::Current.token_info.present? && Array.wrap(Current.token_info[:token_scopes]).include?(:ai_workflows)
      end
    end
  end
end
