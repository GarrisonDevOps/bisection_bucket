# frozen_string_literal: true

module EE
  module ServicePing
    module InstanceIdentity
      extend ::Gitlab::Utils::Override

      private

      override :unique_instance_id
      def unique_instance_id
        return super if ::CloudConnector.gitlab_realm_saas?

        ::CloudConnector::Tokens.cloud_connector_instance_uid || super
      end
    end
  end
end
