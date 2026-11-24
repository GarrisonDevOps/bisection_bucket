# frozen_string_literal: true

module Ai
  # Returns the foundational chat agents the user may select, filtered by namespace
  # enablement, licence, and the Orbit setting.
  class FoundationalChatAgentsFinder
    include ::Gitlab::Utils::StrongMemoize

    def initialize(current_user, project_id: nil, namespace_id: nil)
      @current_user = current_user
      @project_id = project_id
      @namespace_id = namespace_id
    end

    def execute
      enabled_agents.reject { |agent| agent_disabled?(agent) }.sort_by(&:id)
    end

    private

    attr_reader :current_user, :project_id, :namespace_id

    def enabled_agents
      return enabled_agents_in_namespace if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

      enabled_agents_in_organization(::Organizations::Organization.default_organization)
    end

    def enabled_agents_in_namespace
      namespace = resolve_namespace

      unless namespace && Ability.allowed?(current_user, :read_namespace, namespace)
        return ::Ai::FoundationalChatAgent.only_duo_chat_agent
      end

      agents = namespace.enabled_foundational_agents

      return agents if namespace.licensed_feature_available?(:ai_features)

      agents.reject(&:ultimate_only)
    end

    def enabled_agents_in_organization(organization)
      agents = organization.enabled_foundational_agents

      return agents if ::License.feature_available?(:ai_features)
      return agents.reject(&:ultimate_only) if ::GitlabSubscriptions::Duo.active_self_managed_gitlab_credits?

      agents
    end

    def agent_disabled?(agent)
      orbit_agent_disabled?(agent) || onboarding_guide_disabled?(agent)
    end

    def orbit_agent_disabled?(agent)
      return false unless agent.reference == 'orbit_agent'

      # For anonymous callers we don't filter here: upstream
      # namespace/license filters handle access control.
      return false unless current_user

      !::Ai::Orbit::Settings.agent_enabled?(current_user)
    end

    def onboarding_guide_disabled?(agent)
      return false unless agent.reference == 'onboarding_guide'

      # On GitLab.com the root namespace is the actor, so individual
      # top-level groups can be enabled via ChatOps. Self-managed has no
      # meaningful namespace actor, so nil applies the global flag state.
      actor = resolve_namespace if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

      !::Feature.enabled?(:onboarding_guide_agent, actor)
    end

    def resolve_namespace
      return unless current_user

      current_root_namespace = find_object(project_id || namespace_id)&.root_ancestor
      current_user.governing_namespace(current_root_namespace)
    end
    strong_memoize_attr :resolve_namespace

    def find_object(id)
      return unless id

      ::Gitlab::Graphql::Lazy.force(GitlabSchema.object_from_id(id))
    end
  end
end
