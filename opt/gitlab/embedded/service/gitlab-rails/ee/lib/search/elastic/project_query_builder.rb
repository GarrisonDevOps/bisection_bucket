# frozen_string_literal: true

module Search
  module Elastic
    class ProjectQueryBuilder < QueryBuilder
      extend ::Gitlab::Utils::Override

      DOC_TYPE = 'project'
      FIELDS = %w[name^10 name_with_namespace^2 path_with_namespace path^9 description].freeze

      QUERY_COMPONENTS = {
        ::Search::Elastic::Filters => %i[by_type by_archived by_search_level_and_membership],
        ::Search::Elastic::Formats => %i[source_fields page size],
        ::Search::Elastic::Sorts::Base => %i[sort_by]
      }.freeze

      SCORE_COMPONENTS = {
        ::Search::Elastic::Scores => [:wrap]
      }.freeze

      private

      override :extra_options
      def extra_options
        {
          doc_type: DOC_TYPE,
          project_id_field: :id
        }
      end

      override :prepare_options
      def prepare_options
        options[:fields] = options[:fields].presence || FIELDS
        options[:restrict_to_membership] = true if options[:autocomplete] && options[:current_user]

        options[:score_functions] = [
          ::Search::Elastic::Scores.field_value_function(field: 'star_count'),
          ::Search::Elastic::Scores.filter_weight_function(filter: { term: { forked: true } }, weight: 0.5)
        ]
      end

      override :build_initial_query_hash
      def build_initial_query_hash
        ::Search::Elastic::Queries.by_full_text(query: query, options: options)
      end
    end
  end
end
