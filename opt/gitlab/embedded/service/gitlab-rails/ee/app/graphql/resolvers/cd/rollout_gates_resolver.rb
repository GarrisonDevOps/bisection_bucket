# frozen_string_literal: true

module Resolvers
  module Cd
    class RolloutGatesResolver < BaseResolver
      type [::Types::Cd::RolloutGateType], null: true

      alias_method :rollout, :object

      def resolve
        return unless Feature.enabled?(:ai_native_deploy, current_user)

        BatchLoader::GraphQL.for(rollout.id).batch do |rollout_ids, loader|
          gates_by_rollout_id = ::Cd::RolloutGate.for_rollouts(rollout_ids)

          rollout_ids.each { |rollout_id| loader.call(rollout_id, gates_by_rollout_id.fetch(rollout_id, [])) }
        end
      end
    end
  end
end
