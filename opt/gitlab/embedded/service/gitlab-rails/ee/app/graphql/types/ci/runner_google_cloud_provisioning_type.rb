# frozen_string_literal: true

module Types
  module Ci
    class RunnerGoogleCloudProvisioningType < BaseObject
      graphql_name 'CiRunnerGoogleCloudProvisioning'
      description 'Information used for runner Google Cloud provisioning.'

      SHELL_SCRIPT_TEMPLATE_PATH = 'ee/lib/api/templates/google_cloud_integration_runner_project_setup.sh.erb'

      include Gitlab::Graphql::Authorize::AuthorizeResource

      authorize :read_runner_cloud_provisioning_info

      field :project_setup_shell_script, GraphQL::Types::String, null: true,
        description: 'Instructions for setting up a Google Cloud project.'

      field :provisioning_steps,
        null: true,
        resolver: ::Resolvers::Ci::RunnerGoogleCloudProvisioningStepsResolver

      def self.authorized?(object, context)
        super(object[:container], context)
      end

      def project_setup_shell_script
        template = ERB.new(File.read(Rails.root.join(SHELL_SCRIPT_TEMPLATE_PATH)))

        locals = {
          google_cloud_project_id: google_cloud_project_id
        }

        template.result_with_hash(locals)
      end

      private

      def google_cloud_project_id
        object[:cloud_project_id]
      end
    end
  end
end
