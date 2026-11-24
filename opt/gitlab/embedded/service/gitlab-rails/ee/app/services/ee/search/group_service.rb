# frozen_string_literal: true

module EE
  module Search
    module GroupService
      include ::Gitlab::Utils::StrongMemoize

      extend ::Gitlab::Utils::Override
      include ::Search::AdvancedAndZoektSearchable

      override :elasticsearchable_scope
      def elasticsearchable_scope
        group unless global_elasticsearchable_scope?
      end

      override :zoekt_searchable_scope
      def zoekt_searchable_scope
        group
      end

      def zoekt_group_id
        group.id
      end

      override :search_level
      def search_level
        :group
      end

      override :zoekt_node_id
      def zoekt_node_id; end

      override :elastic_global
      def elastic_global
        false
      end

      def elasticsearch_results
        ::Search::Elastic::GroupSearchResults.new(
          current_user,
          params[:search],
          group: group,
          public_and_internal_projects: elastic_global,
          order_by: params[:order_by],
          sort: params[:sort],
          filters: filters
        )
      end

      override :allowed_scopes
      def allowed_scopes
        scopes = ::Search::Scopes.available_for_context(
          context: :group,
          container: group,
          requested_search_type: params[:search_type]
        )

        if group.respond_to?(:licensed_feature_available?) && group.licensed_feature_available?(:epics)
          scopes + %w[epics]
        else
          scopes - %w[epics]
        end
      end
    end
  end
end
