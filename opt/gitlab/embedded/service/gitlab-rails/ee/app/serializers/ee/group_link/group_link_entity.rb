# frozen_string_literal: true

module EE
  module GroupLink
    module GroupLinkEntity
      extend ActiveSupport::Concern

      prepended do
        include GroupLinksHelper
        include ProjectLinksHelper

        expose :access_level, override: true do
          expose :human_access, as: :string_value
          expose :group_access, as: :integer_value
          expose :member_role_id, if: ->(link) { custom_role_assignable?(link) }
        end

        expose :custom_roles do |link|
          custom_roles(link)
        end

        private

        def custom_roles(link)
          return [] unless custom_role_assignable?(link)

          member_roles = ::MemberRoles::RolesFinder.new(current_user, { parent: link.member_role_owner }).execute

          member_roles.map do |member_role|
            {
              base_access_level: member_role.base_access_level,
              member_role_id: member_role.id,
              name: member_role.name,
              description: member_role.description
            }
          end
        end

        def custom_role_assignable?(link)
          return custom_role_for_project_link_enabled?(link.project) if link.is_a?(::ProjectGroupLink)

          link.shared_group.custom_roles_enabled?
        end
      end
    end
  end
end
