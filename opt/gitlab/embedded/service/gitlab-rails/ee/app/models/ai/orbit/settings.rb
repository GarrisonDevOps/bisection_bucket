# frozen_string_literal: true

module Ai
  module Orbit
    module Settings
      # Each subsetting gates Orbit in a Duo flow, keyed by the flow's
      # workflow_definition: agent -> 'orbit_agent/v1', chat -> 'chat',
      # foundational -> other foundational agents, custom_agents -> Ai::Catalog agents.
      SUBSETTINGS = {
        agent: 'orbit_agent_enabled',
        chat: 'orbit_agentic_chat_enabled',
        foundational: 'orbit_other_foundational_agents_enabled',
        custom_agents: 'orbit_custom_agents_enabled'
      }.freeze

      PARTICIPATING_CACHE_KEY = 'orbit_participating_namespace'
      POSITIVE_CACHE_PERIOD = 30.minutes
      NEGATIVE_CACHE_PERIOD = 2.minutes

      class << self
        def agent_enabled?(user)
          subsetting_enabled?(user, :agent)
        end

        def chat_enabled?(user)
          subsetting_enabled?(user, :chat)
        end

        def foundational_enabled?(user)
          subsetting_enabled?(user, :foundational)
        end

        def custom_agents_enabled?(user)
          subsetting_enabled?(user, :custom_agents)
        end

        def orbit_in_duo_on?(user)
          return false unless user
          return false unless ::Analytics::KnowledgeGraph.enabled_for?(user)

          if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
            participating_namespace?(user)
          else
            ::Gitlab::CurrentSettings.orbit_dap_enabled_by_default &&
              ::Analytics::KnowledgeGraph::OrbitLicense.available_for?(user)
          end
        end

        def expire_participating_cache(user)
          Rails.cache.delete(participating_cache_key(user))
        end

        private

        # Cached per user because it runs on every Duo flow start via McpConfigService.
        def participating_namespace?(user)
          key = participating_cache_key(user)

          cached = Rails.cache.read(key)
          return cached unless cached.nil?

          participating = ::Analytics::KnowledgeGraph::GoverningNamespaceFinder.for(user).candidates.exists?
          ttl = participating ? POSITIVE_CACHE_PERIOD : NEGATIVE_CACHE_PERIOD

          Rails.cache.write(key, participating, expires_in: ttl)

          participating
        end

        def participating_cache_key(user)
          ['users', user.id, PARTICIPATING_CACHE_KEY]
        end

        def subsetting_enabled?(user, subsetting)
          return false unless orbit_in_duo_on?(user)

          user.user_preference.orbit_settings.fetch(SUBSETTINGS.fetch(subsetting), true)
        end
      end
    end
  end
end
