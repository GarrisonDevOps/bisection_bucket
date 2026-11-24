# frozen_string_literal: true

module EE
  module API
    module Entities
      module Member
        extend ActiveSupport::Concern

        prepended do
          # EE attributes
          expose :group_saml_identity,
            using: ::API::Entities::Identity,
            if: ->(member, options) { member.user && Ability.allowed?(options[:current_user], :read_group_saml_identity, member.source) }

          expose :group_scim_identity,
            using: ::API::Entities::ScimIdentity,
            if: ->(member, options) { member.user && Ability.allowed?(options[:current_user], :read_group_scim_identity, member.source) }

          expose(
            :email,
            if: ->(member, options) {
              options[:current_user]&.can_admin_all_resources? || member.user&.can_read_email_enterprise_user?(options[:current_user], group: member.source&.root_ancestor)
            }
          ) do |member, _options|
            member.user&.email
          end

          expose :is_using_seat, if: ->(_, options) { options[:show_seat_info] }

          expose :override, if: ->(member, _) { member.source_type == 'Namespace' && member.ldap? }

          expose :human_state_name, as: :membership_state
          expose :member_role, with: ::API::Entities::MemberRole, expose_nil: false
        end
      end
    end
  end
end
