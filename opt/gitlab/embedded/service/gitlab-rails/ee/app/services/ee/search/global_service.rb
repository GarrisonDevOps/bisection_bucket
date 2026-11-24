# frozen_string_literal: true

module EE
  module Search
    module GlobalService
      extend ::Gitlab::Utils::Override
      include ::Gitlab::Utils::StrongMemoize
      include ::Search::AdvancedAndZoektSearchable

      def elasticsearch_results
        ::Gitlab::Elastic::SearchResults.new(
          current_user,
          params[:search],
          public_and_internal_projects: elastic_global,
          order_by: params[:order_by],
          sort: params[:sort],
          filters: filters
        )
      end

      override :zoekt_searchable_scope?
      def zoekt_searchable_scope?
        true
      end

      override :search_level
      def search_level
        :global
      end

      override :root_ancestor
      def root_ancestor; end

      override :zoekt_node_id
      def zoekt_node_id; end

      def zoekt_nodes
        @zoekt_nodes ||= ::Search::Zoekt::Node.for_search.searchable
      end

      def elasticsearchable_scope
        nil
      end

      def elastic_global
        true
      end

      def zoekt_project_id; end

      def zoekt_group_id; end
    end
  end
end
