# frozen_string_literal: true

module Subscriptions
  module Cd
    class ServiceUpdated < ::Subscriptions::BaseSubscription
      include Gitlab::Graphql::Laziness

      argument :application_id, ::Types::GlobalIDType[::Cd::Application],
        required: true,
        description: 'Global ID of the application whose services to watch.'

      payload_type ::Types::Cd::ServiceType

      def authorized?(application_id:)
        # On a subscription update `self.object` is the service payload, so force
        # resolution of the application from the GID by passing `object: nil`.
        authorize_object_or_gid!(:read_cd_application, gid: application_id, object: nil)
      end
    end
  end
end
