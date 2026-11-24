# frozen_string_literal: true

module Subscriptions
  module Cd
    class ApplicationHealthUpdated < ::Subscriptions::BaseSubscription
      include Gitlab::Graphql::Laziness

      argument :organization_id, ::Types::GlobalIDType[::Organizations::Organization],
        required: true,
        description: 'Global ID of the organization whose application health to watch.'

      payload_type ::Types::Cd::ApplicationType

      def authorized?(organization_id:)
        # On a subscription update `self.object` is the application payload, so force
        # resolution of the organization from the GID by passing `object: nil`.
        authorize_object_or_gid!(:read_cd_application, gid: organization_id, object: nil)
      end
    end
  end
end
