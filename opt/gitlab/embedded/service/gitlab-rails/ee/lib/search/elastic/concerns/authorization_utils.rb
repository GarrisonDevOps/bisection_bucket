# frozen_string_literal: true

module Search
  module Elastic
    module Concerns
      module AuthorizationUtils
        extend Gitlab::Cache::RequestCache
        include Search::Concerns::FeatureCustomAbilityMap

        # One query for all groups: LATERAL with LIMIT keeps a per-group index probe that stops at the first
        # project. A plain EXISTS gets planned as a hash join over all projects.
        GROUPS_WITH_PROJECTS_JOIN = <<~SQL.squish
          INNER JOIN LATERAL (
            SELECT 1 FROM namespaces descendants
            WHERE descendants.type = 'Group'
              AND descendants.traversal_ids >= namespaces.traversal_ids
              AND descendants.traversal_ids < next_traversal_ids_sibling(namespaces.traversal_ids)
              AND (SELECT 1 FROM projects WHERE projects.namespace_id = descendants.id LIMIT 1) IS NOT NULL
            LIMIT 1
          ) with_projects ON TRUE
        SQL
        GROUPS_WITH_PROJECTS_BATCH_SIZE = 1_000

        private

        # Returns the required minimum access level for a feature for non-private and private projects.
        # @param feature [Symbol] The feature for which to retrieve the access levels.
        def get_feature_access_levels(feature)
          {
            project: ProjectFeature.required_minimum_access_level(feature),
            private_project: ProjectFeature.required_minimum_access_level_for_private_project(feature)
          }
        end

        # Returns the projects for a given user based on the search level and options.
        # @param user [User] The user for whom to retrieve projects.
        # @param options [Hash] Options for filtering projects.
        # @option options [Symbol] :search_level The level of search (e.g., :global, :group, :project).
        # @option options [Array<Integer>] :group_ids Optional:
        #   An array of group IDs to filter by (for :group search_level).
        # @option options [Array<Integer>] :project_ids Optional:
        #   An array of project IDs to filter by (for :project search_level).
        # @return [ActiveRecord::Relation<Project>] A relation of authorized projects.
        def projects_for_user(user, options)
          return Project.none unless user

          search_level = options.fetch(:search_level).to_sym

          authorized_projects = ::Gitlab::SafeRequestStore.fetch("user:#{user.id}-projects_for_search") do
            ::Search::ProjectsFinder.new(user: user).execute.inc_routes
          end

          case search_level
          when :global
            authorized_projects
          when :group
            namespace_ids = options[:group_ids]
            Project.from_union([
              authorized_projects.in_namespace(namespace_ids),
              authorized_projects.by_any_overlap_with_traversal_ids(namespace_ids)
            ])
          when :project
            project_ids = options[:project_ids]
            projects = Project.id_in(project_ids)
            return Project.none if projects.empty?

            projects.id_not_in(authorized_projects).empty? ? projects : authorized_projects.id_in(projects)
          end
        end

        # @param current_user [User] The user for whom to scope project IDs.
        # @param project_ids [Array<Integer>, Symbol] An array of project IDs to filter, or :any to allow all projects.
        # @return [Array<Integer>, Symbol] The scoped project IDs, or :any if no scoping is needed.
        #   Returns an empty array if cross-project search is restricted and multiple project IDs are provided.
        def scoped_project_ids(current_user, project_ids)
          return :any if project_ids == :any

          project_ids ||= []

          # When reading cross project is not allowed, only allow searching a
          # a single project, so the `:read_*` ability is only checked once.
          return [] if !Ability.allowed?(current_user, :read_cross_project) && project_ids.size > 1

          project_ids
        end

        # Returns the groups for a given user based on the minimum access level.
        # @param user [User] The user for whom to retrieve groups.
        # @param min_access_level [Integer] Optional: The minimum access level required for groups.
        def groups_for_user(user:, min_access_level: nil)
          ::Gitlab::SafeRequestStore.fetch("user:#{user&.id}-min_access_level:#{min_access_level}-groups_for_search") do
            ::Search::GroupsFinder.new(user: user, params: { min_access_level: min_access_level }).execute
          end
        end

        # Returns the traversal IDs for a given user's authorized groups based on the search level and options.
        # @param user [User] The user for whom to retrieve traversal IDs.
        # @param options [Hash] Options for filtering traversal IDs.
        # @option options [Integer] :min_access_level Optional: The minimum access level required for groups.
        # @return [Array<Array<Integer>>] An array of arrays, where each inner array represents a traversal ID path.
        def traversal_ids_for_user(user, options)
          return [] unless user

          authorized_groups = groups_for_user(user: user, min_access_level: options[:min_access_level])

          format_traversal_ids(traversal_ids_for_search_level(authorized_groups, options))
        end

        # Returns the traversal IDs for a given user based on the search level and options.
        # @param authorized_groups [ActiveRecord::Relation<Group>] The groups authorized for the user.
        # @param options [Hash] Options for filtering traversal IDs.
        # @option options [Symbol] :search_level The level of search (e.g., :global, :group, :project).
        # @option options [Array<Integer>] :group_ids Optional:
        #   An array of group IDs to filter by (for :group search_level).
        # @option options [Array<Integer>] :project_ids Optional:
        #   An array of project IDs to filter by (for :project search_level).
        # @return [Array<Array<Integer>>] An array of arrays, where each array represents a traversal ID path.
        def traversal_ids_for_search_level(authorized_groups, options)
          search_level = options.fetch(:search_level).to_sym

          case search_level
          when :global
            authorized_traversal_ids_for_global(authorized_groups)
          when :group
            authorized_traversal_ids_for_groups(authorized_groups, options[:group_ids])
          when :project
            authorized_traversal_ids_for_projects(authorized_groups, options[:project_ids])
          end
        end

        def format_traversal_ids(traversal_ids)
          traversal_ids.map { |id_array| "#{id_array.join('-')}-" }
        end

        def authorized_traversal_ids_for_global(authorized_groups)
          ::Namespaces::Traversal::TrieNode.build(authorized_groups.map(&:traversal_ids)).to_a
        end

        def authorized_traversal_ids_for_groups(authorized_groups, namespace_ids)
          namespaces = Namespace.id_in(namespace_ids)

          return namespaces.map(&:traversal_ids) unless namespaces.id_not_in(authorized_groups).exists?

          authorized_trie = ::Namespaces::Traversal::TrieNode.build(authorized_groups.map(&:traversal_ids))

          [].tap do |allowed_traversal_ids|
            namespaces.map do |namespace|
              traversal_ids = namespace.traversal_ids
              if authorized_trie.covered?(traversal_ids)
                allowed_traversal_ids << traversal_ids
                next
              end

              allowed_traversal_ids.concat(authorized_trie.prefix_search(traversal_ids))
            end
          end
        end

        # Returns authorized traversal_ids for the list of projects
        # @param authorized_groups [ActiveRecord::Relation<Group>] The groups authorized for the user.
        # @param project_ids [Array<Integer>] An array of project IDs to filter by.
        # @return [Array<Array<Integer>>] Uses trie node approach to return list of authorized traversal_ids
        def authorized_traversal_ids_for_projects(authorized_groups, project_ids)
          namespace_ids = Project.id_in(project_ids).select(:namespace_id)
          namespaces = Namespace.id_in(namespace_ids)

          return namespaces.map(&:traversal_ids) unless namespaces.id_not_in(authorized_groups).exists?

          authorized_trie = ::Namespaces::Traversal::TrieNode.build(authorized_groups.map(&:traversal_ids))

          namespaces.map(&:traversal_ids).select { |s| authorized_trie.covered?(s) }
        end

        # Mirrors `current_user.authorized_groups.self_and_ancestors`: every id on the
        # traversal path of an authorized group is that group or one of its ancestors.
        # @param user [User] The user for whom to retrieve ancestor ids.
        # @return [Array<Integer>]
        def authorized_group_ancestor_ids(user, options)
          groups_for_user(user: user, min_access_level: options[:min_access_level])
            .flat_map(&:traversal_ids).uniq
        end

        def ancestry_filter(namespace_ancestry, traversal_id_field:)
          context.name(:ancestry_filter) do
            namespace_ancestry.map do |namespace_ids|
              {
                prefix: {
                  "#{traversal_id_field}": {
                    _name: context.name(:descendants),
                    value: namespace_ids
                  }
                }
              }
            end
          end
        end

        # Memoizes for the request, since two filters call this per query build.
        # @param user [User] The user for whom to retrieve authorized namespace IDs.
        # @return [Array<Integer>] Authorized traversal_ids
        def authorized_namespace_ids_for_project_group_ancestry(user)
          ::Gitlab::SafeRequestStore.fetch("user:#{user&.id}-project_group_ancestry_for_search") do
            uncached_authorized_namespace_ids_for_project_group_ancestry(user)
          end
        end

        # @param user [User] The user for whom to retrieve authorized namespace IDs.
        # @return [Array<Integer>] Uses trie node approach to return authorized traversal_ids
        def uncached_authorized_namespace_ids_for_project_group_ancestry(user)
          authorized_groups = ::Search::GroupsFinder.new(user: user).execute
          authorized_projects = ::Search::ProjectsFinder.new(user: user).execute.inc_routes
          authorized_project_namespaces = Namespace.id_in(authorized_projects.select(:namespace_id))

          unless ::Feature.enabled?(:advanced_search_project_ancestors_via_groups, user)
            return legacy_authorized_namespace_ids_for_project_group_ancestry(authorized_groups,
              authorized_project_namespaces)
          end

          authorized_trie = ::Namespaces::Traversal::TrieNode.build(authorized_groups.map(&:traversal_ids))

          # A project grants its namespace's ancestors (GroupPolicy has_projects). Those from the first authorized
          # group down already match by traversal_ids prefix, but the ones above it need their ids.
          project_ancestor_ids = authorized_project_namespaces.pluck(:traversal_ids).flat_map do |traversal_ids| # rubocop:disable CodeReuse/ActiveRecord -- traversal_ids are needed to generate namespace_id array
            depth = (1..traversal_ids.size).find { |size| authorized_trie.covered?(traversal_ids.first(size)) }
            depth ? traversal_ids.first(depth - 1) : traversal_ids
          end

          (project_ancestor_ids + ancestor_ids_of_groups_with_projects(authorized_groups, authorized_trie)).uniq
        end

        # Search::ProjectsFinder leaves out projects reached through a group, but any project under an authorized
        # group grants the ancestors above it. Only the topmost authorized groups below a root have such ancestors.
        def ancestor_ids_of_groups_with_projects(authorized_groups, authorized_trie)
          candidates = authorized_groups.select do |group|
            ancestor_ids = group.traversal_ids[0...-1]
            ancestor_ids.any? && !authorized_trie.covered?(ancestor_ids)
          end
          return [] if candidates.empty?

          traversal_ids_type = ::Namespace.traversal_ids_type
          with_projects = candidates.each_slice(GROUPS_WITH_PROJECTS_BATCH_SIZE).flat_map do |batch|
            group_ids_with_projects(batch, traversal_ids_type)
          end.to_set

          candidates.select { |group| with_projects.include?(group.id) }
            .flat_map { |group| group.traversal_ids[0...-1] }
        end

        # Passes in the groups' traversal_ids, already loaded, so the query doesn't read the group rows again.
        def group_ids_with_projects(groups, traversal_ids_type)
          candidates = ::Namespace.sanitize_sql_array([
            "SELECT id, traversal_ids::#{traversal_ids_type} AS traversal_ids " \
              'FROM unnest(ARRAY[?]::bigint[], ARRAY[?]::text[]) AS candidates(id, traversal_ids)',
            groups.map(&:id), groups.map { |group| "{#{group.traversal_ids.join(',')}}" }
          ])

          ::Namespace.from("(#{candidates}) namespaces").joins(GROUPS_WITH_PROJECTS_JOIN).pluck(:id) # rubocop:disable CodeReuse/ActiveRecord -- search-only authorization query
        end

        # Remove with the advanced_search_project_ancestors_via_groups flag: https://gitlab.com/gitlab-org/gitlab/-/work_items/638697
        def legacy_authorized_namespace_ids_for_project_group_ancestry(authorized_groups, authorized_project_namespaces)
          return [] unless authorized_project_namespaces.id_not_in(authorized_groups).exists?

          authorized_trie = ::Namespaces::Traversal::TrieNode.build(authorized_groups.map(&:traversal_ids))
          not_covered_namespaces = authorized_project_namespaces.reject do |namespace|
            authorized_trie.covered?(namespace.traversal_ids)
          end

          not_covered_namespaces.pluck(:traversal_ids).flatten.uniq # rubocop:disable CodeReuse/ActiveRecord -- traversal_ids are needed to generate namespace_id array
        end

        def allowed_ids_by_ability(feature:, user_abilities:)
          target_ability = FEATURE_TO_ABILITY_MAP[feature.to_sym]
          user_abilities.filter_map do |id, abilities|
            id if abilities.include?(target_ability)
          end
        end
      end
    end
  end
end
