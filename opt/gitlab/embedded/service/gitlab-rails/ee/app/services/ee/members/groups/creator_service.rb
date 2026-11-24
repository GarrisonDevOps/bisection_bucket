# frozen_string_literal: true

module EE
  module Members
    module Groups
      module CreatorService
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        override :execute
        def execute
          super.tap do |m|
            m.update_user_group_member_roles(old_values_map: {
              access_level: m.attribute_before_last_save(:access_level),
              member_role_id: m.attribute_before_last_save(:member_role_id)
            })
          end
        end

        class_methods do
          extend ::Gitlab::Utils::Override

          private

          override :parsed_args
          def parsed_args(args)
            super.merge(ignore_user_limits: args[:ignore_user_limits])
          end
        end

        private

        override :member_attributes
        def member_attributes
          attributes = super.merge(ignore_user_limits: ignore_user_limits)
          top_level_group = source.root_ancestor

          return attributes unless top_level_group.custom_roles_enabled?

          attributes.merge(member_role_id: member_role_id)
        end

        override :can_create_new_member?
        def can_create_new_member?
          return false unless service_account_eligible_for_membership?

          if member.user&.service_account?
            Ability.allowed?(current_user, :admin_service_account_member, member.group)
          else
            Ability.allowed?(current_user, :invite_group_members, member.group)
          end
        end

        def ignore_user_limits
          args[:ignore_user_limits]
        end

        def member_role_id
          args[:member_role_id]
        end
      end
    end
  end
end
