# frozen_string_literal: true

module Ai
  module DuoAgentPlatform
    module AccessPolicy
      extend ActiveSupport::Concern

      included do
        condition(:duo_agent_platform_enabled, scope: :subject) do
          ::Ai::DuoWorkflow.duo_agent_platform_available?(@subject)
        end

        # A service account running an autonomous trigger: no human identity to
        # intersect permissions against, so it acts on its own authority. Triggers
        # are project-scoped, so a group subject has none to match against.
        condition(:autonomous_service_account) do
          next false unless user_is_user?
          next false unless @subject.is_a?(::Project)
          next false unless @user.service_account? && !@user.composite_identity_enforced?
          next false unless ::Feature.enabled?(:autonomous_service_account_execution, @subject)
          next false unless @user.sa_provisioned_for_project?(@subject)

          ::Ai::FlowTrigger.for_autonomous_service_account(@user, @subject).active.exists?
        end

        condition(:duo_workflow_available) do
          next false unless user_is_user?
          next false unless @subject.duo_features_enabled
          next false unless ::Gitlab::Llm::StageCheck.available?(@subject, :duo_workflow)
          next true if @user.allowed_to_use?(:duo_agent_platform, root_namespace: @subject.root_ancestor)

          # Such an account cannot hold a Duo add-on seat, so backing an active
          # trigger is what entitles it instead.
          autonomous_service_account?
        end

        # Mirrors the checks of :access_code_suggestions in GlobalPolicy. Project and
        # group policies do not delegate to the global policy, so they need their
        # own copy.
        condition(:code_suggestions_licensed, scope: :global) do
          next true if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
          next true if ::GitlabSubscriptions::Duo.active_self_managed_gitlab_credits?

          ::License.feature_available?(:code_suggestions)
        end

        condition(:code_suggestions_enabled_for_user) do
          next false unless @user

          @user.allowed_to_use?(:code_suggestions, root_namespace: @subject.root_ancestor)
        end
      end
    end
  end
end
