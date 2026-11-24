# frozen_string_literal: true

module Search
  module ZoektSearchable
    include ::Gitlab::Utils::StrongMemoize

    # TODO: rename to search_code_with_zoekt?
    # https://gitlab.com/gitlab-org/gitlab/-/issues/421619
    def use_zoekt?
      return false unless ::Search::Zoekt.search_enabled? && zoekt_searchable_scope?

      zoekt_node_available_for_search?
    end

    def zoekt_searchable_scope
      raise NotImplementedError
    end

    def search_level
      raise NotImplementedError
    end

    def zoekt_searchable_scope?
      zoekt_searchable_scope.try(:search_code_with_zoekt?)
    end

    def root_ancestor
      zoekt_searchable_scope&.root_ancestor
    end

    def zoekt_projects
      raise ArgumentError, 'Using zoekt projects for group search is no longer supported' if use_traversal_id_queries?

      @zoekt_projects ||= projects # rubocop:disable Gitlab/ModuleWithInstanceVariables -- legacy code
    end

    def zoekt_filters
      params.slice(:language, :include_archived, :exclude_forks, :num_context_lines)
    end

    def zoekt_node_id
      zoekt_nodes.first&.id
    end
    strong_memoize_attr :zoekt_node_id

    def zoekt_nodes
      # Note: there will be more zoekt nodes whenever replicas are introduced.
      @zoekt_nodes ||= zoekt_searchable_scope.root_ancestor.zoekt_enabled_namespace.nodes.for_search.searchable
    end

    def zoekt_node_available_for_search?
      zoekt_nodes.exists?
    end

    def use_traversal_id_queries?
      ::Search::Zoekt.feature_available?(
        :traversal_id_search, current_user, group_id: zoekt_group_id, project_id: zoekt_project_id
      )
    end

    def zoekt_search_results
      ::Search::Zoekt::SearchResults.new(
        current_user,
        params[:search],
        use_traversal_id_queries? ? nil : zoekt_projects,
        source: params[:source],
        node_id: zoekt_node_id,
        chunk_count: params[:chunk_count],
        filters: zoekt_filters,
        modes: { regex: params[:regex] },
        group_id: zoekt_group_id,
        project_id: zoekt_project_id
      )
    end
  end
end
