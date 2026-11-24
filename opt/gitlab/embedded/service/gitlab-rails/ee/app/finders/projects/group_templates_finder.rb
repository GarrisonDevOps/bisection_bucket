# frozen_string_literal: true

module Projects
  class GroupTemplatesFinder
    include Gitlab::Utils::StrongMemoize

    def initialize(user, group_id)
      @user = user
      @group_id = group_id
    end

    def execute
      return Project.none unless templates_available?

      ::Project
        .in_namespace(template_groups)
        .public_or_visible_to_user(user)
        .not_aimed_for_deletion
        .non_archived
        .with_route
        .projects_order_namespace_id_asc
        .with_order_id_asc
    end

    private

    attr_reader :user, :group_id

    def group
      # Preloading the inherited settings keeps the :create_projects check below at a constant
      # query count: both the archived and scheduled-for-deletion conditions read from it
      # instead of walking ancestors per call.
      # rubocop: disable CodeReuse/ActiveRecord -- preloading here is the point, see comment above
      Group.with_route.preload(:namespace_settings_with_ancestors_inherited_settings).find_by_id(group_id)
      # rubocop: enable CodeReuse/ActiveRecord
    end
    strong_memoize_attr :group

    def templates_available?
      user && group && Ability.allowed?(user, :create_projects, group) && group.group_project_template_available?
    end

    def template_groups
      ::Namespaces::TemplateSetting
        .with_namespace_ids(group.self_and_ancestors.select(:id))
        .with_custom_project_templates
        .select(:custom_project_templates_group_id)
    end
  end
end
