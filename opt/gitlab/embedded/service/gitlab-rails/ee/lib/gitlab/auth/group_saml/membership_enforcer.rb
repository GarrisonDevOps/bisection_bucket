# frozen_string_literal: true

module Gitlab
  module Auth
    module GroupSaml
      class MembershipEnforcer
        def initialize(group, project: nil)
          @group = group
          @project = project
        end

        def can_add_user?(user)
          return true unless root_group.saml_provider&.enforced_sso?
          return true if user.project_bot? || user.security_policy_bot?
          return true if user.service_account? && sa_provisioned_in_allowed_hierarchy?(user)

          if inactive_scim_identity_for_group?(user)
            log_audit_event(user, root_group)
            return false
          end

          GroupSamlIdentityFinder.new(user: user).find_linked(group: root_group)
        end

        private

        def root_group
          @root_group ||= @group.root_ancestor
        end

        def inactive_scim_identity_for_group?(user)
          scim_identities = root_group.scim_identities.for_user(user)
          inactive_identities = scim_identities.reject(&:active?)
          inactive_identities.any?
        end

        def sa_provisioned_in_allowed_hierarchy?(user)
          provisioned_within_sso_domain?(user) &&
            ::Members::ServiceAccounts::EligibilityChecker.new(**eligibility_checker_args).eligible?(user)
        end

        def provisioned_within_sso_domain?(user)
          provisioning_root_id = user.provisioned_by_group&.root_ancestor&.id
          provisioning_root_id ||= user.provisioned_by_project&.root_ancestor&.id

          provisioning_root_id == root_group.id
        end

        def eligibility_checker_args
          return { target_project: @project } if @project

          { target_group: @group }
        end

        def log_audit_event(user, root_group)
          audit_context = {
            name: "inactive_scim_user_cannot_be_added",
            author: user,
            scope: root_group,
            target: user,
            target_details: user.username,
            message: "User cannot be added to group due to inactive SCIM identity"
          }
          ::Gitlab::Audit::Auditor.audit(audit_context)
        end
      end
    end
  end
end
