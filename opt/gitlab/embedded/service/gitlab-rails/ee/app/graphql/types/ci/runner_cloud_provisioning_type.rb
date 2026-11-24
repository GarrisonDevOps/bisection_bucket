# frozen_string_literal: true

module Types
  module Ci
    class RunnerCloudProvisioningType < BaseUnion
      graphql_name 'CiRunnerCloudProvisioning'
      description 'Information used in runner cloud provisioning.'

      include Gitlab::Graphql::Authorize::AuthorizeResource

      UnexpectedProviderType = Class.new(StandardError)

      possible_types ::Types::Ci::RunnerGoogleCloudProvisioningType, ::Types::Ci::RunnerGkeProvisioningType

      def self.resolve_type(object, _context)
        case object[:provider]
        when :google_cloud
          ::Types::Ci::RunnerGoogleCloudProvisioningType
        when :gke

          ::Types::Ci::RunnerGkeProvisioningType
        else
          raise UnexpectedProviderType, 'Unsupported CI runner cloud provider'
        end
      end
    end
  end
end
