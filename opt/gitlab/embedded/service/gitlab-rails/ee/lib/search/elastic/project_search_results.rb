# frozen_string_literal: true

module Search
  module Elastic
    # Always prefer to use the full class namespace when specifying a
    # superclass inside a module, because autoloading can occur in a
    # different order between execution environments.
    class ProjectSearchResults < Gitlab::Elastic::SearchResults
      extend Gitlab::Utils::Override

      attr_reader :project, :filters

      def initialize(current_user, query, project:, **opts)
        @project = project
        @original_repository_ref = opts.fetch(:repository_ref, nil)

        super(
          current_user,
          query,
          root_ancestor_ids: opts.fetch(:root_ancestor_ids, nil),
          public_and_internal_projects: false,
          order_by: opts.fetch(:order_by, nil),
          sort: opts.fetch(:sort, nil),
          filters: opts.fetch(:filters, {})
        )
      end

      # Lazily compute the repository reference only when needed.
      # This avoids unnecessary evaluation (and potential errors)
      # when the repository reference isn't required, for example, for work item searches.
      def repository_ref
        @repository_ref ||= @original_repository_ref.presence || project.default_branch
      end

      private

      def blobs(page: 1, per_page: DEFAULT_PER_PAGE, count_only: false, preload_method: nil)
        return Kaminari.paginate_array([]) if project.empty_repo? || query.blank?
        return Kaminari.paginate_array([]) unless Ability.allowed?(@current_user, :read_code, project)

        strong_memoize(memoize_key(:blobs, count_only: count_only)) do
          project.repository.__elasticsearch__.elastic_search_as_found_blob(
            query,
            page: (page || 1).to_i,
            per: per_page,
            options: scope_options(:blobs).merge(count_only: count_only),
            preload_method: preload_method
          )
        end
      end

      def wiki_blobs(page: 1, per_page: DEFAULT_PER_PAGE, count_only: false)
        return Kaminari.paginate_array([]) unless project.wiki_enabled? && !project.wiki.empty? && query.present?
        return Kaminari.paginate_array([]) unless Ability.allowed?(@current_user, :read_wiki, project)

        strong_memoize(memoize_key(:wiki_blobs, count_only: count_only)) do
          project.wiki.__elasticsearch__.elastic_search_as_wiki_page(
            query,
            page: (page || 1).to_i,
            per: per_page,
            options: scope_options(:wiki_blobs).merge(count_only: count_only)
          )
        end
      end

      def notes(count_only: false)
        strong_memoize(memoize_key(:notes, count_only: count_only)) do
          Note.elastic_search(query,
            options: base_options.merge(filters.slice(:include_archived), count_only: count_only))
        end
      end

      def commits(page: 1, per_page: DEFAULT_PER_PAGE, preload_method: nil, count_only: false)
        return Kaminari.paginate_array([]) if project.empty_repo? || query.blank?
        return Kaminari.paginate_array([]) unless Ability.allowed?(@current_user, :read_code, project)

        strong_memoize(memoize_key(:commits, count_only: count_only)) do
          project.repository.find_commits_by_message_with_elastic(
            query,
            page: (page || 1).to_i,
            per_page: per_page,
            preload_method: preload_method,
            options: base_options.merge(count_only: count_only)
          )
        end
      end

      def blob_aggregations
        return [] if project.empty_repo? || query.blank?
        return [] unless Ability.allowed?(@current_user, :read_code, project)

        strong_memoize(:blob_aggregations) do
          project.repository.__elasticsearch__.blob_aggregations(query, base_options)
        end
      end

      override :base_options
      def base_options
        super.merge(search_level: 'project', project_ids: [project.id])
      end

      override :scope_options
      def scope_options(scope)
        case scope
        when :blobs
          base_options.merge(filters.slice(:language, :num_context_lines))
        when :users
          super.merge(project_id: project.id)
        when :merge_requests
          options = super
          options[:related_ids] = related_ids_for_notes(MergeRequest.name)

          options
        else
          super
        end
      end

      override :work_item_scope_options
      def work_item_scope_options(scope: nil)
        super.merge(root_ancestor_ids: [project.root_ancestor.id])
      end
    end
  end
end
