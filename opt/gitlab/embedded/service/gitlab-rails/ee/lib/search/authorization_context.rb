# frozen_string_literal: true

module Search
  class AuthorizationContext
    include ::Search::Elastic::Concerns::AuthorizationUtils

    def initialize(current_user)
      @current_user = current_user
    end

    def get_access_levels_for_feature(feature)
      get_feature_access_levels(feature)
    end

    def get_traversal_ids_for_group(group_id)
      ::Group.find(group_id).elastic_namespace_ancestry
    end

    def get_groups_with_custom_roles(authorized_groups)
      return Group.none if authorized_groups.empty?

      user_abilities = ::Authz::Group.new(current_user, scope: authorized_groups).permitted

      Group.id_in(allowed_ids_by_ability(feature: 'repository', user_abilities: user_abilities))
    end

    def get_projects_with_custom_roles(authorized_projects)
      return Project.none if authorized_projects.empty?

      user_abilities = ::Authz::Project.new(current_user, scope: authorized_projects).permitted

      Project.id_in(allowed_ids_by_ability(feature: 'repository', user_abilities: user_abilities))
    end

    # Supported options:
    # search_level
    # group_ids
    # project_ids
    def get_formatted_traversal_ids_for_groups(authorized_groups, options)
      format_traversal_ids(traversal_ids_for_search_level(authorized_groups, options))
    end

    # Supported options:
    # min_access_level
    def get_groups_for_user(options)
      groups_for_user(user: current_user, min_access_level: options[:min_access_level])
    end

    # Supported options:
    # search_level
    # group_ids
    # project_ids
    def get_traversal_ids_for_search_level(authorized_groups, options)
      traversal_ids_for_search_level(authorized_groups, options)
    end

    # Supported options:
    # search_level
    # min_access_level
    # group_ids
    # project_ids
    def get_projects_for_user(options)
      return Project.none if anonymous_user?

      min_access_level = options.fetch(:min_access_level)
      projects_for_user(current_user, options).where_exists(current_user.authorizations_for_projects(min_access_level:))
    end

    def admin_user?
      return false if anonymous_user?

      current_user.can_read_all_resources?
    end

    def anonymous_user?
      current_user.nil?
    end

    private

    attr_reader :current_user
  end
end
