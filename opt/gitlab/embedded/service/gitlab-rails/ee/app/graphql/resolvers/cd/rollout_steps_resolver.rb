# frozen_string_literal: true

module Resolvers
  module Cd
    class RolloutStepsResolver < BaseResolver
      type [::Types::Cd::RolloutStepType], null: true

      alias_method :rollout, :object

      def resolve
        return unless Feature.enabled?(:ai_native_deploy, current_user)

        rollout.rollout_steps.top_level.ordered
      end
    end
  end
end
