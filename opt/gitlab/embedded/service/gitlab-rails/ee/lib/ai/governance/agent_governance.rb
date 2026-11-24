# frozen_string_literal: true

module Ai
  module Governance
    module AgentGovernance
      # Whether GitLab AI Agent Governance records external agent sessions for the project.
      # Projects in a personal namespace on GitLab.com have no group to turn AI Governance on.
      def self.enabled_for?(project)
        return false if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) &&
          !project.root_ancestor.group_namespace?

        project.ai_governance_enabled
      end

      # Whether to tell the user that governance is off for the project, rather than answer
      # with the usual 403. Only users who can read the project's governance setting are told, so it
      # is not visible to everyone who can see a public project. While ai_governance_session_gate
      # is off, sessions are gated on duo_external_agents_enabled instead, so nothing is reported.
      def self.report_disabled_to?(user, project)
        ::Feature.enabled?(:ai_governance_session_gate, project.root_ancestor) &&
          !enabled_for?(project) &&
          Ability.allowed?(user, :read_ai_agent_governance, project)
      end
    end
  end
end
