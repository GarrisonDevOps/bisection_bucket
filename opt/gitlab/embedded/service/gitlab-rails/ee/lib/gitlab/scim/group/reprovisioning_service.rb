# frozen_string_literal: true

module Gitlab
  module Scim
    module Group
      class ReprovisioningService
        include GitlabSubscriptions::MemberManagement::SeatAwareProvisioning

        attr_reader :identity

        delegate :user, :group, to: :identity

        def initialize(identity)
          @identity = identity
        end

        def execute
          GroupScimIdentity.transaction do
            identity.update!(active: true)
            add_member unless existing_member?
          end
        end

        private

        def add_member
          access_level_adjustment = calculate_adjusted_access_level(group, user, default_membership_role)
          member = group.add_member(user, access_level_adjustment.access_level, member_role_id: member_role_id)

          if member.persisted? && access_level_adjustment.adjusted?
            track_and_audit_minimal_access_provisioning(
              group, member, default_membership_role, { scim_identity_id: identity.id }
            )
          end

          member
        end

        def default_membership_role
          group.saml_provider.default_membership_role
        end

        def member_role_id
          group.saml_provider.member_role_id
        end

        def existing_member?
          ::GroupMember.member_of_group?(group, user)
        end
      end
    end
  end
end
