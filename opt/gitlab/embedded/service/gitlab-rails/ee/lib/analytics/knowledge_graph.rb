# frozen_string_literal: true

module Analytics
  module KnowledgeGraph
    # Whether the Knowledge Graph (GKG) gRPC service is wired up on this
    # instance. Reads the instance-level `knowledge_graph.enabled` config
    # (gitlab.yml / Helm chart value `global.appConfig.knowledgeGraph.enabled`).
    def self.service_configured?
      !!Gitlab.config.knowledge_graph['enabled']
    rescue Gitlab::Configs::MissingConfig
      false
    end

    # Single source of truth for Orbit availability: the service must be
    # configured on this instance.
    def self.enabled_for?(_user)
      service_configured?
    end

    # Availability plus the licensing/tier check (delegated to OrbitLicense).
    def self.accessible_for?(user)
      enabled_for?(user) && OrbitLicense.available_for?(user)
    end

    # On GitLab.com each check reads Redis, and one GraphQL request can ask for many groups.
    def self.status_accessible_for_request?(user)
      ::Gitlab::SafeRequestStore.fetch([:orbit_status_accessible_for, user&.id]) do
        enabled_for?(user) && OrbitLicense.status_available_for?(user)
      end
    end
  end
end
