# frozen_string_literal: true

module EE
  module RapidDiffs
    module MergeRequestPresenter
      extend ::Gitlab::Utils::Override

      override :new_comment_template_paths
      def new_comment_template_paths
        paths = super
        project = resource.project
        group = project.group

        if project && can?(current_user, :create_saved_reply, project)
          paths << {
            text: _('Project comment templates'),
            href: project_comment_templates_path(project)
          }
        end

        if group && can?(current_user, :create_saved_reply, group)
          paths << {
            text: _('Group comment templates'),
            href: group_comment_templates_path(group)
          }
        end

        paths
      end

      override :user_permissions
      def user_permissions
        super.merge(
          can_resolve_discussions_with_ai: resource.can_resolve_discussions_with_ai?(current_user)
        )
      end
    end
  end
end
