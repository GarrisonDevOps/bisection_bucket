# frozen_string_literal: true

module EE
  module Import
    module SourceUsers
      module ReassignService
        extend ::Gitlab::Utils::Override
        include ::Gitlab::Utils::StrongMemoize

        private

        override :valid_assignee?
        def valid_assignee?
          return true if super

          service_account_reassignment?
        end

        override :run_validations
        def run_validations
          validation_error = super

          return validation_error if validation_error

          return error_invalid_assignee_due_to_sso_enforcement unless valid_assignee_if_sso_enforcement_is_applicable?

          return if valid_assignee_if_should_check_enterprise_users?

          error_invalid_assignee_due_to_enterprise_users_check
        end

        override :skip_reassignment_confirmation?
        def skip_reassignment_confirmation?
          return true if super

          enterprise_skip_reassignment_confirmation? || service_account_reassignment?
        end

        def valid_assignee_if_sso_enforcement_is_applicable?
          ::Gitlab::Auth::GroupSaml::MembershipEnforcer.new(root_namespace).can_add_user?(assignee_user)
        end

        def error_invalid_assignee_due_to_sso_enforcement
          ServiceResponse.error(
            message: invalid_assignee_due_to_sso_enforcement_message,
            reason: :invalid_assignee,
            payload: import_source_user
          )
        end

        def valid_assignee_if_should_check_enterprise_users?
          return true unless root_namespace.any_enterprise_users?

          assignee_user.managed_by_group?(root_namespace) || valid_non_enterprise_member_assignee?
        end

        def valid_non_enterprise_member_assignee?
          return false unless root_namespace.allow_non_enterprise_placeholder_reassignment?

          ::Member.user_in_hierarchy_or_invited_groups?(assignee_user.id, root_namespace)
        end

        def enterprise_skip_reassignment_confirmation?
          ::Import::UserMapping::EnterpriseBypassAuthorizer.new(root_namespace, assignee_user, current_user).allowed?
        end
        strong_memoize_attr :enterprise_skip_reassignment_confirmation?

        def service_account_reassignment?
          ::Import::UserMapping::ServiceAccountBypassAuthorizer.new(root_namespace, assignee_user,
            current_user).allowed?
        end
        strong_memoize_attr :service_account_reassignment?

        def error_invalid_assignee_due_to_enterprise_users_check
          ServiceResponse.error(
            message: invalid_assignee_due_to_enterprise_users_check_message,
            reason: :invalid_assignee,
            payload: import_source_user
          )
        end

        def invalid_assignee_due_to_enterprise_users_check_message
          if root_namespace.allow_non_enterprise_placeholder_reassignment?
            s_("UserMapping|You can assign only enterprise users or existing members of the top-level group " \
              "you're importing to, its subgroups, or its projects.")
          else
            s_("UserMapping|You can assign only enterprise users in the top-level group you're importing to.")
          end
        end

        def invalid_assignee_due_to_sso_enforcement_message
          s_('UserMapping|You can assign only users with linked SAML and SCIM identities. ' \
            'Ensure the user has signed into GitLab through your SAML SSO provider and has an ' \
            'active SCIM identity for this group.')
        end
      end
    end
  end
end
