# frozen_string_literal: true

module Ai
  module FoundationalAgents
    # Decides whether a foundational agent other than Duo Chat is on for a namespace or an organization.
    class EnabledResolver
      # Picks the rule for the container: the switch gates every agent only where the readiness card is on.
      #
      # @param container [Namespace, Organizations::Organization]
      # @return [EnabledResolver]
      def self.for(container)
        gated_by_switch = container.is_a?(::Namespace) &&
          ::Feature.enabled?(:duo_group_agent_readiness_settings, container.root_ancestor, type: :beta)

        new(default_enabled: container.foundational_agents_default_enabled, gated_by_switch: gated_by_switch)
      end

      # @param default_enabled [Boolean] the Foundational agents switch
      # @param gated_by_switch [Boolean] whether the switch gates every agent
      def initialize(default_enabled:, gated_by_switch:)
        @default_enabled = default_enabled
        @gated_by_switch = gated_by_switch
      end

      # Whether the agent is on, given its own setting.
      #
      # @param agent_setting [Boolean, nil] the agent's own setting, nil when it has none
      # @return [Boolean]
      def enabled?(agent_setting)
        return false if gated_by_switch && !default_enabled
        return agent_setting unless agent_setting.nil?

        default_enabled
      end

      private

      attr_reader :default_enabled, :gated_by_switch
    end
  end
end
