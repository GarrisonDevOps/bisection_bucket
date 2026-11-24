# frozen_string_literal: true

module Search
  module Zoekt
    class AccessBranchBuilder
      include Gitlab::Utils::StrongMemoize

      REPO_ENABLED = ::Featurable::ENABLED # 20
      REPO_PRIVATE = ::Featurable::PRIVATE # 10
      VIS_PUBLIC = ::Gitlab::VisibilityLevel::PUBLIC # 20
      VIS_INTERNAL = ::Gitlab::VisibilityLevel::INTERNAL # 10

      def initialize(current_user, auth, options)
        @current_user = current_user
        @options = options
        @auth = auth
      end

      def build
        return [admin_branch] if admin_access?
        return [public_branch] if anonymous_user?

        access_branches = [public_and_internal_branch]
        access_branches.concat(public_and_internal_authorized_branches)
        access_branches.concat(private_authorized_branches)

        access_branches
      end

      private

      attr_reader :current_user, :options, :auth

      def admin_access?
        current_user&.can_read_all_resources?
      end

      def anonymous_user?
        current_user.blank?
      end

      def group_id
        @group_id ||= options[:group_id]
      end

      def project_id
        @project_id ||= options[:project_id]
      end

      def group_ids
        @group_ids ||= [group_id].compact
      end

      def project_ids
        @project_ids ||= [project_id].compact
      end

      def access_levels
        @access_levels ||= auth.get_access_levels_for_feature(options[:features])
      end

      def public_and_internal_authorized_projects
        @public_and_internal_authorized_projects ||= authorized_projects(access_levels[:project])
      end

      def public_and_internal_authorized_groups
        @public_and_internal_authorized_groups ||= authorized_groups(access_levels[:project])
      end

      def private_groups
        @private_groups ||= authorized_groups(access_levels[:private_project])
      end

      def private_project_ids
        @private_project_ids ||= authorized_project_ids(access_levels[:private_project])
      end

      def custom_role_groups
        @custom_role_groups ||= auth.get_groups_with_custom_roles(public_and_internal_authorized_groups)
      end

      def custom_role_projects
        @custom_role_projects ||= auth.get_projects_with_custom_roles(public_and_internal_authorized_projects)
      end

      def public_and_internal_authorized_branches
        filters = build_public_internal_auth_filters
        return [] if filters.empty?

        [public_and_internal_with_access_branch(filters)]
      end

      def build_public_internal_auth_filters
        [].tap do |filters|
          filters.concat(group_filters_for(public_and_internal_authorized_groups))
          filters.concat(project_filters_for(public_and_internal_authorized_projects))
        end
      end

      def private_authorized_branches
        filters = build_private_auth_filters
        return [] if filters.empty?

        [private_branch(filters)]
      end

      def build_private_auth_filters
        [].tap do |filters|
          filters.concat(group_filters_for(private_groups))
          filters.concat(group_filters_for(custom_role_groups))
          filters.concat(project_filters_for_ids(private_project_ids))
          filters.concat(project_filters_for(custom_role_projects))
        end
      end

      def group_filters_for(groups)
        return [] unless groups.exists?

        # If we need to enforce project limits (not using traversal IDs),
        # skip group filters to avoid searching too many projects
        return [] if should_limit_projects?

        traversal_ids = authorized_traversal_ids_for_groups(groups)
        traversal_ids.map { |t| Filters.by_traversal_ids(t) }
      end

      def project_filters_for(projects)
        return [] unless projects.exists?

        project_ids = projects.pluck_primary_key
        project_filters_for_ids(apply_project_limit(project_ids))
      end

      def project_filters_for_ids(project_ids)
        return [] if project_ids.blank?

        project_ids = apply_project_limit(project_ids)
        [Filters.by_repo_ids(project_ids)]
      end

      def apply_project_limit(project_ids)
        return project_ids unless should_limit_projects?

        project_ids[0...::Search::Zoekt::Settings.max_projects_for_legacy_search]
      end

      def should_limit_projects?
        # Only limit if all conditions are met:
        # 1. Searching at group level (not project-specific)
        # 2. Traversal ID search is not available (we have to enumerate all individual projects)
        return false unless group_id.present?
        return false if traversal_id_search_available?

        true
      end

      def traversal_id_search_available?
        ::Search::Zoekt.feature_available?(
          :traversal_id_search, current_user, group_id: group_id, project_id: project_id
        )
      end
      strong_memoize_attr :traversal_id_search_available?

      def authorized_traversal_ids_for_groups(groups)
        auth.get_formatted_traversal_ids_for_groups(groups,
          group_ids: group_ids,
          project_ids: project_ids,
          search_level: options.fetch(:search_level))
      end

      def authorized_projects(min_access_level)
        auth.get_projects_for_user(
          group_ids: group_ids,
          project_ids: project_ids,
          min_access_level: min_access_level,
          search_level: options.fetch(:search_level)
        )
      end

      def authorized_groups(min_access_level)
        auth.get_groups_for_user(
          group_ids: group_ids,
          project_ids: project_ids,
          min_access_level: min_access_level,
          search_level: options.fetch(:search_level)
        )
      end

      def authorized_project_ids(min_access_level)
        authorized_projects(min_access_level).pluck_primary_key
      end

      def admin_branch
        Filters.by_meta(
          key: 'repository_access_level', value: "#{REPO_ENABLED}|#{REPO_PRIVATE}",
          context: { name: 'admin_branch' }
        )
      end

      def public_branch
        Filters.and_filters(
          Filters.by_meta(key: 'visibility_level', value: VIS_PUBLIC),
          Filters.by_meta(key: 'repository_access_level', value: REPO_ENABLED),
          context: { name: 'public_branch' }
        )
      end

      def public_and_internal_with_access_branch(filters)
        Filters.and_filters(
          Filters.by_meta(key: 'visibility_level', value: "#{VIS_PUBLIC}|#{VIS_INTERNAL}"),
          Filters.by_meta(key: 'repository_access_level', value: REPO_PRIVATE),
          Filters.or_filters(*filters, context: { name: 'user_authorizations' }),
          context: { name: 'public_and_internal_authorized_branch' }
        )
      end

      def public_and_internal_branch
        Filters.and_filters(
          Filters.by_meta(key: 'visibility_level', value: "#{VIS_PUBLIC}|#{VIS_INTERNAL}"),
          Filters.by_meta(key: 'repository_access_level', value: REPO_ENABLED),
          context: { name: 'public_and_internal_branch' }
        )
      end

      def private_branch(filters)
        Filters.and_filters(
          Filters.by_meta(key: 'repository_access_level', value: "#{REPO_ENABLED}|#{REPO_PRIVATE}"),
          Filters.or_filters(*filters, context: { name: 'user_authorizations' }),
          context: { name: 'private_authorized_branch' }
        )
      end
    end
  end
end
