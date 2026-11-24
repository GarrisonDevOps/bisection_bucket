# frozen_string_literal: true

module EE
  module Search
    module ProjectService
      extend ::Gitlab::Utils::Override
      include ::Gitlab::Utils::StrongMemoize
      include ::Gitlab::Loggable
      include ::Search::AdvancedAndZoektSearchable

      SCOPES_THAT_SUPPORT_BRANCHES = %w[wiki_blobs commits blobs].freeze

      # project search always includes archived and forked projects
      override :zoekt_filters
      def zoekt_filters
        super.merge(include_archived: true, exclude_forks: false)
      end

      override :search_type
      def search_type
        use_default_branch? ? super : 'basic'
      end

      def elasticsearch_results
        search = params[:search]
        order_by = params[:order_by]
        sort = params[:sort]

        ::Search::Elastic::ProjectSearchResults.new(
          current_user,
          search,
          project: project,
          root_ancestor_ids: [project.root_ancestor.id],
          repository_ref: repository_ref,
          order_by: order_by,
          sort: sort,
          filters: filters
        )
      end

      def repository_ref
        params[:repository_ref]
      end

      def use_default_branch?
        return true if repository_ref.blank?
        return true unless SCOPES_THAT_SUPPORT_BRANCHES.include?(scope)

        project.root_ref?(repository_ref)
      end

      override :elasticsearchable_scope
      def elasticsearchable_scope
        project unless global_elasticsearchable_scope?
      end

      override :zoekt_searchable_scope
      def zoekt_searchable_scope
        project
      end

      def zoekt_project_id
        project.id
      end

      def zoekt_group_id; end

      override :search_level
      def search_level
        :project
      end

      override :zoekt_projects
      def zoekt_projects
        @zoekt_projects ||= ::Project.id_in(project)
      end

      override :zoekt_nodes
      def zoekt_nodes
        @zoekt_nodes ||= ::Search::Zoekt::Node.searchable_for_project(zoekt_searchable_scope)
      end

      override :zoekt_node_available_for_search?
      def zoekt_node_available_for_search?
        return true if super
        return true if empty_repo_searchable_with_zoekt?

        index_project_without_zoekt_repository
        false
      end
      strong_memoize_attr :zoekt_node_available_for_search?

      private

      # An empty repository has nothing to index, so Zoekt returns no results instead of falling back.
      def empty_repo_searchable_with_zoekt?
        ::Feature.enabled?(:zoekt_search_empty_repo_without_fallback, project) && project.empty_repo?
      end

      def index_project_without_zoekt_repository
        return unless ::Feature.enabled?(:zoekt_index_project_on_search_fallback, project)
        return unless ::Search::Zoekt::Replica.for_namespace(project.root_ancestor.id).ready.exists?
        return if ::Search::Zoekt::Repository.for_project_id(project.id).exists?
        return if project.empty_repo?

        return unless queue_fallback_indexing

        zoekt_logger.info(build_structured_payload_labkit(
          message: 'Queued indexing for project without Zoekt repository on search fallback',
          Labkit::Fields::GL_PROJECT_ID => project.id
        ))
      end

      def queue_fallback_indexing
        ::Search::Zoekt.with_project_context(project) do
          unless ::Feature.enabled?(:zoekt_search_fallback_skip_wal_check, project)
            next ::Search::Zoekt.index_async(project.id)
          end

          next false unless ::Search::Zoekt.licensed_and_indexing_enabled?

          ::Search::Zoekt::FallbackIndexingTaskWorker.perform_async(project.id)
        end
      end

      def zoekt_logger
        @zoekt_logger ||= ::Search::Zoekt::Logger.build
      end
    end
  end
end
