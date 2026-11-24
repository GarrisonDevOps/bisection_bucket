# frozen_string_literal: true

module Resolvers
  module Ci
    class RunnerGoogleCloudProvisioningStepsResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      type [Types::Ci::RunnerCloudProvisioningStepType], null: true
      description 'Steps used to provision a runner in the cloud.'

      argument :ephemeral_machine_type, ::Types::GoogleCloud::MachineTypeType,
        required: true,
        description: 'Name of the machine type to use for running jobs.'
      argument :region, ::Types::GoogleCloud::RegionType,
        required: true,
        description: 'Name of the region to provision the runner in.'
      argument :runner_token, ::GraphQL::Types::String,
        required: false,
        default_value: nil,
        description: 'Authentication token of the runner.'
      argument :zone, ::Types::GoogleCloud::ZoneType,
        required: true,
        description: 'Name of the zone to provision the runner in.'

      # object is a hash normally sent by EE::Types::ProjectType#runner_cloud_provisioning, containing the
      # arguments used in the provisioning.
      alias_method :provisioning_args_hash, :object

      def resolve(region:, zone:, ephemeral_machine_type:, runner_token:)
        container = provisioning_args_hash[:container]

        unless Ability.allowed?(current_user, :provision_cloud_runner, container)
          raise_resource_not_available_error!("You don't have permissions to provision cloud runners")
        end

        response = ::Ci::Runners::CreateGoogleCloudProvisioningStepsService.new(
          container: container,
          current_user: current_user,
          params: {
            google_cloud_project_id: provisioning_args_hash[:cloud_project_id], runner_token: runner_token,
            region: region, zone: zone, ephemeral_machine_type: ephemeral_machine_type
          }
        ).execute

        raise_resource_not_available_error!(response.message) if response.error?

        response.payload[:provisioning_steps]
      end
    end
  end
end
