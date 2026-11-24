# frozen_string_literal: true

module Types
  module Ci
    class RunnerGkeProvisioningType < BaseObject
      graphql_name 'CiRunnerGkeProvisioning'
      description 'Information used for GKE runner provisioning.'

      include Gitlab::Graphql::Authorize::AuthorizeResource

      SHELL_SCRIPT_TEMPLATE_PATH = 'ee/lib/api/templates/gke_integration_grit_provisioning_setup.sh.erb'

      authorize :read_runner_gke_provisioning_info

      field :project_setup_shell_script, GraphQL::Types::String, null: true,
        description: 'Instructions for setting up a Google Cloud project.'

      field :provisioning_steps,
        resolver: ::Resolvers::Ci::RunnerGkeProvisioningStepsResolver

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
