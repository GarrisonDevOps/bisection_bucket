# frozen_string_literal: true

module Ci
  module Runners
    class CreateGkeProvisioningStepsService < BaseContainerService
      DEPLOYMENT_NAME_MAX_LENGTH = 20
      DEPLOYMENT_NAME_REGEXP = /^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$\Z/ # See https://cloud.google.com/compute/docs/naming-resources
      TEMPLATES_LOCATION = %w[ee lib api templates].freeze
      TERRAFORM_TEMPLATE_PATH = File.join(*TEMPLATES_LOCATION, 'gke_integration_grit_provisioning.tf.erb')
      SHELL_TEMPLATE_PATH = File.join(*TEMPLATES_LOCATION, 'gke_integration_grit_provisioning.sh.erb')

      def execute
        validation_error = validate
        return validation_error if validation_error

        ServiceResponse.success(payload: {
          provisioning_steps: [
            {
              title: s_('Runners|Save the Terraform script to a file'),
              language_identifier: 'terraform',
              instructions: instructions[:terraform_script]
            },
            {
              title: s_('Runners|Apply the Terraform script'),
              language_identifier: 'shell',
              instructions: instructions[:shell_script]
            }
          ]
        })
      end

      private

      def validate
        unless Ability.allowed?(current_user, :provision_gke_runner, container)
          return ServiceResponse.error(
            message: s_('Runners|The user is not allowed to provision a GKE runner'),
            reason: :insufficient_permissions
          )
        end

        if runner_token.present? && runner.nil?
          return ServiceResponse.error(
            message: s_('Runners|The runner authentication token is invalid'),
            reason: :invalid_argument
          )
        end

        if runner.nil? && !Ability.allowed?(current_user, :create_runners, container)
          return ServiceResponse.error(
            message: s_('Runners|The user is not allowed to create a runner'),
            reason: :insufficient_permissions
          )
        end

        return if deployment_name.match?(DEPLOYMENT_NAME_REGEXP)

        ServiceResponse.error(
          message: s_('Runners|The deployment name is invalid'),
          payload: { deployment_name: deployment_name },
          reason: :internal_error
        )
      end

      def deployment_name
        # Unique in context of Google Cloud project, no longer than DEPLOYMENT_NAME_MAX_LENGTH characters
        unique_id = runner&.short_sha || Devise.friendly_token(Ci::Runner::RUNNER_SHORT_SHA_LENGTH)
        "grit-#{unique_id}"[0..DEPLOYMENT_NAME_MAX_LENGTH - 1].downcase.tr('_', '-').gsub(/-+$\Z/, '')
      end
      strong_memoize_attr :deployment_name

      def runner
        return unless runner_token.present?

        ::Ci::Runner.find_by_token(runner_token)
      end
      strong_memoize_attr :runner

      def instructions
        terraform_template = ERB.new(File.read(Rails.root.join(TERRAFORM_TEMPLATE_PATH)))
        shell_template = ERB.new(File.read(Rails.root.join(SHELL_TEMPLATE_PATH)))

        locals = {
          provisioning_project_id: provisioning_project_id,
          provisioning_region: provisioning_region,
          provisioning_zone: provisioning_zone,
          deployment_name: deployment_name
        }.transform_values { |user_input| sanitize_value(user_input) }.merge(
          gitlab_project_id: container.id,
          gitlab_url: Gitlab.config.gitlab.url,
          gitlab_runner_token: runner_token,
          node_pools: node_pools
        )

        {
          terraform_script: terraform_template.result_with_hash(locals),
          shell_script: shell_template.result_with_hash(locals)
        }
      end
      strong_memoize_attr :instructions

      def sanitize_value(user_input)
        # Ensure the variable name starts with a letter and only contains letters, digits, underscores, and hyphens
        user_input&.gsub(/[^a-zA-Z0-9_-]\Z/, '_')
      end

      def provisioning_project_id
        params[:google_cloud_project_id]
      end

      def provisioning_region
        params[:region]
      end

      def provisioning_zone
        params[:zone]
      end

      def runner_token
        params[:runner_token]
      end

      def node_pools
        params[:node_pools]
      end
    end
  end
end
