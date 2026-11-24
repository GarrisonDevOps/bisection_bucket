# frozen_string_literal: true

module EE
  module AccessTokensHelper
    extend ::Gitlab::Utils::Override

    override :personal_access_token_data
    def personal_access_token_data(token, user = current_user)
      super.deep_merge(
        access_token: {
          agentic_available: user.foundational_agent_available?('duo_permissions_assistant').to_s
        }
      )
    end

    override :show_group_access_tokens_premium_offer?
    def show_group_access_tokens_premium_offer?(group)
      return false if can?(current_user, :create_resource_access_tokens, group)
      return false unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
      return false unless can?(current_user, :read_billing, group.root_ancestor)

      group.root_ancestor.plan_name_for_upgrading == ::GitlabSubscriptions::SystemDefined::Plan::FREE
    end

    override :show_project_access_token_upgrade_card?
    def show_project_access_token_upgrade_card?(project)
      return false unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
      return false unless project.group
      return false if project.root_ancestor.licensed_feature_available?(:resource_access_token)
      return false if can?(current_user, :create_resource_access_tokens, project)

      can?(current_user, :read_billing, project.root_ancestor)
    end

    private

    override :max_date_allowed
    def max_date_allowed
      return super unless personal_access_token_expiration_policy_enabled?

      personal_access_token_max_expiry_date&.iso8601
    end

    override :max_expiration_days
    def max_expiration_days
      return super unless personal_access_token_expiration_policy_enabled?

      personal_access_token_max_expiry_days
    end
  end
end
