# frozen_string_literal: true

module Search
  module Elastic
    class UserQueryBuilder < QueryBuilder
      extend ::Gitlab::Utils::Override

      DOC_TYPE = 'user'
      SEARCH_FIELDS = %w[email name public_email username].freeze

      QUERY_COMPONENTS = {
        ::Search::Elastic::Filters => %i[by_forbidden_states by_user_accessible_namespaces],
        ::Search::Elastic::Formats => %i[size source_fields],
        ::Search::Elastic::Sorts::Base => %i[sort_by]
      }.freeze

      private

      override :extra_options
      def extra_options
        {
          doc_type: DOC_TYPE,
          no_join_project: true,
          project_id_field: nil,
          fuzzy_operator: 'AND'
        }
      end

      override :prepare_options
      def prepare_options
        options[:fields] = valid_fields
      end

      override :build_initial_query_hash
      def build_initial_query_hash
        if ::Search::Elastic::Queries::ADVANCED_QUERY_SYNTAX_REGEX.match?(query)
          ::Search::Elastic::Queries.by_full_text(query: query, options: options)
        else
          ::Search::Elastic::Queries.by_fuzzy_text(query: query, options: options)
        end
      end

      def valid_fields
        user = options[:current_user]
        return SEARCH_FIELDS if user&.can_admin_all_resources?

        SEARCH_FIELDS - ['email']
      end
    end
  end
end
