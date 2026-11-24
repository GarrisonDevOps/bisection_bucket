# frozen_string_literal: true

module Search
  module Elastic
    class GroupQueryBuilder < QueryBuilder
      extend ::Gitlab::Utils::Override

      DOC_TYPE = 'group'
      FIELDS = %w[name^3 full_name^2 path^2 full_path description].freeze
      DEFAULT_PAGE = 1
      DEFAULT_PER_PAGE = 20

      QUERY_COMPONENTS = {
        ::Search::Elastic::Filters => %i[
          by_search_level_and_group_membership
          by_authorized_groups_only
          by_parent
          by_top_level
          by_ids
          by_excluded_ids
          by_archived
          by_active
          by_organization
          by_visibility_level
        ],
        ::Search::Elastic::Formats => [
          { method: :source_fields, skip_if_size_zero: true },
          { method: :page, skip_if_size_zero: true },
          { method: :size, skip_if_size_zero: true }
        ],
        ::Search::Elastic::Sorts::Group => [
          { method: :sort_by, skip_if_size_zero: true }
        ]
      }.freeze

      private

      override :extra_options
      def extra_options
        {
          doc_type: DOC_TYPE,
          namespace_visibility_field: :visibility_level,
          traversal_ids_prefix: :traversal_ids,
          # A group document is the namespace, so its own id is what ancestor filters match.
          ancestor_id_field: :id
        }
      end

      override :prepare_options
      def prepare_options
        options[:fields] = fields
        options.reverse_merge!(search_level: :global, order_by: 'updated_at', sort: 'desc', page: DEFAULT_PAGE,
          per_page: DEFAULT_PER_PAGE)
      end

      override :build_initial_query_hash
      def build_initial_query_hash
        ::Search::Elastic::Queries.by_full_text(query: query, options: options)
      end

      def fields
        return options[:fields] if options[:fields].presence

        FIELDS
      end
    end
  end
end
