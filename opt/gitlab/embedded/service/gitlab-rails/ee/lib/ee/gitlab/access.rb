# frozen_string_literal: true

# Gitlab::Access module
#
# Define allowed roles that can be used
# in GitLab code to determine authorization level
#
module EE
  module Gitlab
    module Access
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      MINIMAL_ACCESS_HASH = { "Minimal Access" => ::Gitlab::Access::MINIMAL_ACCESS }.freeze

      class_methods do
        extend ::Gitlab::Utils::Override

        def vulnerability_access_levels
          @vulnerability_access_levels ||= sym_options_with_owner.values_at(:developer, :maintainer, :owner).freeze
        end

        def options_with_minimal_access
          MINIMAL_ACCESS_HASH.merge(options_with_owner)
        end

        def options_for_custom_roles
          options_with_minimal_access.tap { |options| options.delete('Owner') }
        end

        override :values_with_minimal_access
        def values_with_minimal_access
          options_with_minimal_access.values
        end

        override :human_access
        def human_access(access, member_role = nil)
          member_role&.name || options_with_minimal_access.key(access)
        end

        override :human_access_with_none
        def human_access_with_none(access, member_role = nil)
          human_access(access, member_role) || super
        end

        override :option_descriptions
        def option_descriptions
          super.merge({
            ::Gitlab::Access::MINIMAL_ACCESS => s_('MemberRole|The Minimal Access role is for users who need the ' \
              'least amount of access into groups and projects. You can assign this role as a default, before giving ' \
              'a user another role with more permissions.')
          })
        end
      end

      override :human_access
      def human_access
        ::Gitlab::Access.human_access(access_field, member_role)
      end

      override :human_access_with_none
      def human_access_with_none
        ::Gitlab::Access.human_access_with_none(access_field, member_role)
      end

      override :human_access_labeled
      def human_access_labeled
        return super unless member_role

        format(s_('MemberRole|Custom role: %{role}'), role: member_role.name)
      end
    end
  end
end
