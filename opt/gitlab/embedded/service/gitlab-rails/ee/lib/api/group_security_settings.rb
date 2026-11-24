# frozen_string_literal: true

module API
  class GroupSecuritySettings < ::API::Base
    feature_category :security_testing_configuration

    before do
      authenticate!
      check_feature_availability
    end

    helpers do
      def check_feature_availability
        forbidden! unless ::License.feature_available?(:secret_push_protection)
      end
    end

    params do
      requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the group.'
    end

    resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      segment ':id/security_settings' do
        desc 'Update group security settings' do
          detail 'Updates group security settings for a specified group. You must have the Security Manager, ' \
            'Maintainer, or Owner role for the group.'
          tags %w[groups]
        end
        params do
          requires :secret_push_protection_enabled, type: Boolean,
            desc: 'If `true`, enables secret push protection for projects in the group.'
          optional :projects_to_exclude, type: Array[Integer], desc: 'IDs of projects to exclude from secret push ' \
                                                                 'protection.'
        end
        route_setting :tier, :ultimate
        route_setting :authorization, permissions: :update_security_setting, boundary_type: :group
        put do
          unauthorized! unless can?(current_user, :enable_secret_push_protection, user_group)

          enabled = params[:secret_push_protection_enabled]
          projects_to_exclude = params[:projects_to_exclude]

          ::Security::Configuration::SetGroupSecretPushProtectionWorker.perform_async(user_group.id, enabled, current_user.id, projects_to_exclude) # rubocop:disable CodeReuse/Worker -- This is meant to be a background job

          {
            secret_push_protection_enabled: enabled,
            errors: []
          }
        end
      end
    end
  end
end
