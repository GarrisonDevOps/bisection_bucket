# frozen_string_literal: true

module Resolvers
  module Ci
    class RunnerGkeProvisioningStepsResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      type [Types::Ci::RunnerGkeProvisioningStepType], null: true
      description 'Steps used to provision a runner in GKE.'

      argument :node_pools, [::Types::GoogleCloud::NodePoolType],
        required: false,
        default_value: [],
        replace_null_with_default: true,
        description: 'Configuration for the node pools of the runner.'
      argument :region, ::Types::GoogleCloud::RegionType,
        required: true,
        description: 'Name of the region to provision the runner in.'
      argument :runner_token, ::GraphQL::Types::String,
        required: true,
        description: 'Authentication token of the runner.'
      argument :zone, ::Types::GoogleCloud::ZoneType,
        required: true,
        description: 'Name of the zone to provision the runner in.'

      # object is a hash normally sent by EE::Types::ProjectType#runner_cloud_provisioning, containing the
      # arguments used in the provisioning.
      alias_method :provisioning_args_hash, :object

      def resolve(region:, zone:, runner_token:, node_pools:)
        container = provisioning_args_hash[:container]

        return unless Ability.allowed?(current_user, :provision_gke_runner, container)

        response = ::Ci::Runners::CreateGkeProvisioningStepsService.new(
          container: container,
          current_user: current_user,
          params: {
            google_cloud_project_id: provisioning_args_hash[:cloud_project_id], runner_token: runner_token,
            region: region, zone: zone, node_pools: node_pools
          }
        ).execute

        raise_resource_not_available_error!(response.message) if response.error?

        response.payload[:provisioning_steps]
      end
    end
  end
end
