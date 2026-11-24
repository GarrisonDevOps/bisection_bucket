# frozen_string_literal: true

module API
  class ProjectSecuritySettings < ::API::Base
    before { authenticate! }
    before { check_feature_availability }

    helpers do
      def check_feature_availability
        forbidden! unless ::License.feature_available?(:secret_push_protection) ||
          ::License.feature_available?(:dependency_scanning)
      end
    end

    feature_category :secret_detection

    params do
      requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the project.'
    end

    resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      segment ':id/security_settings' do
        desc 'List all project security settings' do
          detail 'Lists all security settings for the project. You must have the Security Manager, ' \
            'Developer, Maintainer, or Owner role for the project.'
          tags %w[projects]
        end
        route_setting :tier, :ultimate
        route_setting :authorization, permissions: :read_security_setting, boundary_type: :project
        get do
          unauthorized! unless can?(current_user, :read_security_settings, user_project)

          present user_project&.security_setting
        end

        desc 'Update project security settings' do
          detail 'Updates project security settings for a specified project. You ' \
            'must have the Maintainer or Owner role for the project.'
          tags %w[projects]
        end
        params do
          optional :secret_push_protection_enabled, type: Boolean, desc: 'If `true`, enables secret push protection ' \
                                                                     'for the project.'
          optional :pre_receive_secret_detection_enabled, type: Boolean,
            desc: 'If `true`, enables secret push protection for the project. ' \
              '[Deprecated](https://gitlab.com/gitlab-org/gitlab/-/issues/514413) in GitLab 17.9. ' \
              'Use `secret_push_protection_enabled` instead.'
          optional :fast_dependency_paths_enabled, type: Boolean,
            desc: 'Deprecated. Has no effect; dependency graph builds always record direct edges only.'
          at_least_one_of :secret_push_protection_enabled, :pre_receive_secret_detection_enabled,
            :fast_dependency_paths_enabled
        end
        route_setting :tier, :ultimate
        route_setting :authorization, permissions: :update_security_setting, boundary_type: :project
        put do
          unauthorized! unless can?(current_user, :update_security_setting, user_project)
          forbidden! if user_project&.self_or_ancestors_archived?

          security_setting = user_project&.security_setting

          if params.key?(:secret_push_protection_enabled) || params.key?(:pre_receive_secret_detection_enabled)
            forbidden! unless ::License.feature_available?(:secret_push_protection)

            enabled = if params.key?(:secret_push_protection_enabled)
                        params[:secret_push_protection_enabled]
                      else
                        params[:pre_receive_secret_detection_enabled]
                      end

            if Gitlab::CurrentSettings.current_application_settings.secret_push_protection_enforced && !enabled
              forbidden!('Secret push protection is enforced for all projects in the instance')
            end

            audit_context = {
              name: 'project_security_setting_updated',
              author: current_user,
              target: user_project,
              scope: user_project,
              message: "User #{current_user.name} updated `secret_push_protection_enabled` to #{enabled}"
            }

            ::Gitlab::Audit::Auditor.audit(audit_context)
            security_setting.set_secret_push_protection!(enabled: enabled)
          end

          if params.key?(:fast_dependency_paths_enabled)
            security_setting.set_fast_dependency_paths!(enabled: params[:fast_dependency_paths_enabled])
          end

          present security_setting
        end
      end
    end
  end
end
