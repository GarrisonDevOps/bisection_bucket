# frozen_string_literal: true

module EE
  module Projects
    module ProjectMembersHelper
      def project_member_header_subtext(project)
        unless can?(current_user, :invite_project_members, project)
          if ::Gitlab::Saas.feature_available?(:group_disable_invite_members)
            return cannot_invite_member_subtext(project.name, "group owner")
          end

          return  cannot_invite_member_subtext(project.name, "instance administrator")

        end

        if project.group &&
            ::Namespaces::FreeUserCap::Enforcement.new(project.root_ancestor).enforce_cap? &&
            can?(current_user, :admin_group_member, project.root_ancestor)
          super + member_header_manage_namespace_members_text(project.root_ancestor)
        else
          super
        end
      end

      private

      def cannot_invite_member_subtext(project_name, actor)
        safe_format(
          _("You cannot invite a new member to %{strong_start}%{project_name}%{strong_end}. " \
            "User invitations are disabled by the %{actor}."),
          tag_pair(tag.strong, :strong_start, :strong_end), project_name: project_name, actor: actor)
      end
    end
  end
end
