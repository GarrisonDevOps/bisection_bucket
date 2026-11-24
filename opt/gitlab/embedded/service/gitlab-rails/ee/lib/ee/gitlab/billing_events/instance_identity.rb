# frozen_string_literal: true

module EE
  module Gitlab
    module BillingEvents
      module InstanceIdentity
        extend ::Gitlab::Utils::Override

        private

        override :realm
        def realm
          raw = ::CloudConnector.gitlab_realm
          ::Gitlab::BillingEvents::InstanceIdentity::REALM_MAP.fetch(raw)
        end

        override :deployment_type
        def deployment_type
          ::CloudConnector.deployment_type
        end

        override :unique_instance_id
        def unique_instance_id
          return super if ::CloudConnector.gitlab_realm == ::CloudConnector::GITLAB_REALM_SAAS

          ::CloudConnector::Tokens.cloud_connector_instance_uid || super
        end
      end
    end
  end
end
