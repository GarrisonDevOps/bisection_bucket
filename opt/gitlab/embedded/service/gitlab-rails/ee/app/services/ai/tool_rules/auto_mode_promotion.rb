# frozen_string_literal: true

module Ai
  module ToolRules
    module AutoModePromotion
      # Not chat, chat_partial or LOCAL, which can stand for chat clients.
      SURFACES = [:ide].freeze

      # A requested project tightens consent like it tightens the rules.
      # @return [Array<String>, nil] nil when the policy must carry no promote key at all
      def self.promote_list(policy:, surface:, container:, requested_project: nil)
        return unless SURFACES.include?(surface&.to_sym)
        return unless container
        return unless Feature.enabled?(:duo_auto_mode_promotion, container.root_ancestor)
        return unless ::Ai::DuoSettings::AutoMode.consented?(container: container)
        return if requested_project && !::Ai::DuoSettings::AutoMode.consented?(container: requested_project)

        policy[:default_ask_tools]
      end
    end
  end
end
