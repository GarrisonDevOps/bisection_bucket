# frozen_string_literal: true

module API
  module Admin
    module Security
      class CompliancePolicySettings < ::API::Base
        before { authenticated_as_admin! }

        feature_category :security_policy_management
        urgency :low

        helpers do
          def ensure_licensed!
            return if ::License.feature_available?(:security_orchestration_policies)

            forbidden!('security_orchestration_policies license feature not available')
          end

          def policy_setting
            @policy_setting ||= ::Security::PolicySetting.in_organization(
              ::Organizations::Organization.default_organization
            )
          end

          def audit_csp_namespace_change(previous_group)
            new_group = policy_setting.csp_namespace

            ::Gitlab::Audit::Auditor.audit(
              name: 'compliance_and_security_policy_group_updated',
              author: current_user,
              scope: ::Gitlab::Audit::InstanceScope.new,
              target: new_group || previous_group,
              message: audit_message_for_csp_change(previous_group, new_group),
              additional_details: { from: previous_group&.full_path, to: new_group&.full_path }
            )
          end

          def audit_message_for_csp_change(previous_group, new_group)
            return "Assigned #{new_group.full_path} as the Compliance and Security Policy group" if previous_group.nil?
            return "Removed #{previous_group.full_path} as the Compliance and Security Policy group" if new_group.nil?

            "Changed the Compliance and Security Policy group from #{previous_group.full_path} " \
              "to #{new_group.full_path}"
          end
        end

        namespace 'admin' do
          namespace 'security' do
            resource :compliance_policy_settings do
              desc 'Retrieve security policy settings' do
                detail 'Retrieves the current security policy settings for this GitLab instance.'
                success ::API::Entities::Admin::Security::PolicySetting
                failure [
                  { code: 401, message: '401 Unauthorized' },
                  { code: 403, message: '403 Forbidden' },
                  { code: 400, message: '400 Bad Request' }
                ]
                tags ['compliance_policy_settings']
              end
              route_setting :tier, :ultimate
              route_setting :authorization, permissions: :read_compliance_policy_setting, boundary_type: :instance,
                assignable_when: [:admin]
              get do
                ensure_licensed!

                present policy_setting, with: ::API::Entities::Admin::Security::PolicySetting
              end

              desc 'Update security policy settings' do
                detail 'Updates the security policy settings for this GitLab instance.'
                success ::API::Entities::Admin::Security::PolicySetting
                failure [
                  { code: 401, message: '401 Unauthorized' },
                  { code: 403, message: '403 Forbidden' },
                  { code: 400, message: '400 Bad Request' },
                  { code: 422, message: '422 Unprocessable Entity' }
                ]
                tags ['compliance_policy_settings']
              end
              params do
                requires :csp_namespace_id,
                  type: Integer,
                  desc: 'ID of the group designated to centrally manage security policies and compliance frameworks. ' \
                    'Must be a top-level group. Set to `null` to clear the setting.'
              end
              route_setting :tier, :ultimate
              route_setting :authorization, permissions: :update_compliance_policy_setting, boundary_type: :instance,
                assignable_when: [:admin]
              put do
                ensure_licensed!

                previous_group = policy_setting.csp_namespace

                if policy_setting.update(declared_params)
                  audit_csp_namespace_change(previous_group) if policy_setting.saved_change_to_csp_namespace_id?

                  present policy_setting, with: ::API::Entities::Admin::Security::PolicySetting
                else
                  unprocessable_entity!(policy_setting.errors.full_messages.join(', '))
                end
              end
            end
          end
        end
      end
    end
  end
end
