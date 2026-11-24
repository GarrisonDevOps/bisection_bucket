# frozen_string_literal: true

module Subscriptions
  module Cd
    class EnvironmentServiceUpdated < ::Subscriptions::BaseSubscription
      include Gitlab::Graphql::Laziness

      argument :environment_id, ::Types::GlobalIDType[::Cd::Environment],
        required: true,
        description: 'Global ID of the environment whose deployed services to watch.'

      payload_type ::Types::Cd::ServiceType

      def authorized?(environment_id:)
        # On a subscription update `self.object` is the service payload, so force
        # resolution of the environment from the GID by passing `object: nil`.
        authorize_object_or_gid!(:read_cd_environment, gid: environment_id, object: nil)
      end
    end
  end
end
