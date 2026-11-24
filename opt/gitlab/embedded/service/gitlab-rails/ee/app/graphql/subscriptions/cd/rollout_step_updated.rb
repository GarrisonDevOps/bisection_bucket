# frozen_string_literal: true

module Subscriptions
  module Cd
    class RolloutStepUpdated < ::Subscriptions::BaseSubscription
      include Gitlab::Graphql::Laziness

      argument :rollout_id, ::Types::GlobalIDType[::Cd::Rollout],
        required: true,
        description: 'Global ID of the rollout whose steps to watch.'

      payload_type ::Types::Cd::RolloutStepType

      def authorized?(rollout_id:)
        authorize_object_or_gid!(:read_cd_rollout, gid: rollout_id, object: nil)
      end
    end
  end
end
