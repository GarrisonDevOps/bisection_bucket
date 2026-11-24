# frozen_string_literal: true

module Resolvers
  module Cd
    class RolloutTransitionsResolver < BaseResolver
      type ::Types::Cd::RolloutTransitionType.connection_type, null: true

      alias_method :rollout, :object

      def resolve
        return unless Feature.enabled?(:ai_native_deploy, current_user)

        rollout.rollout_transitions
      end
    end
  end
end
