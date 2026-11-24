# frozen_string_literal: true

module Elastic
  module Latest
    class WikiClassProxy < ApplicationClassProxy
      include Routing
      include GitClassProxy

      def es_type
        'wiki_blob'
      end

      def elastic_search_as_wiki_page(*args, **kwargs)
        elastic_search_as_found_blob(*args, **kwargs).map! { |blob| Gitlab::Search::FoundWikiPage.new(blob) }
      end

      def elastic_search(
        query, type: es_type, page: Gitlab::SearchResults::DEFAULT_PAGE,
        per: Gitlab::SearchResults::DEFAULT_PER_PAGE, options: {}
      )
        query_hash = search_query(query, options)
        query_hash[:size] = if options[:count_only]
                              0
                            else
                              query_hash[:from] = per * (page - 1)
                              query_hash[:sort] = [:_score]
                              per
                            end

        res = search(query_hash, options)
        { type.pluralize.to_sym => { results: res.results, total_count: res.size } }
      end

      def routing_options(options)
        return {} if routing_disabled?(options)

        ids = options[:root_ancestor_ids].presence || []
        routing = build_routing(ids, prefix: 'n')
        { routing: routing.presence }.compact
      end

      private

      def search_query(query, options)
        search_level = options[:search_level]
        return match_none if search_level == 'group' && options[:group_ids].blank?

        query = build_search_query(query)
        query_hash = build_base_query_hash(query, options)
        query_hash = ::Search::Elastic::Filters.by_search_level_and_membership(query_hash: query_hash,
          options: options.merge({ features: 'wiki' }))
        query_hash = archived_filter(query_hash) if archived_filter_applicable_on_wiki?(options)

        query_hash
      end

      def build_search_query(query)
        ::Gitlab::Search::Query.new(query) do
          filter :filename, field: :file_name
          filter :path, parser: ->(input) { "#{input.downcase}*" }
          filter :extension,
            field: 'file_name.reverse',
            type: :prefix,
            parser: ->(input) { "#{input.downcase.reverse}." }
          filter :blob, field: :oid
        end
      end

      def build_base_query_hash(query, options)
        bool_expr = { filter: [], must: [], must_not: [] }
        query_hash = { query: { bool: bool_expr } }
        bool_expr = apply_simple_query_string(
          name: context.name(:wiki_blob, :match, :search_terms, :separate_index),
          query: query.term,
          fields: %w[content file_name path],
          bool_expr: bool_expr,
          count_only: options[:count_only]
        )

        query_filter_context = query.elasticsearch_filter_context(nil)
        bool_expr[:filter] += query_filter_context[:filter] if query_filter_context[:filter].any?
        bool_expr[:must_not] += query_filter_context[:must_not] if query_filter_context[:must_not].any?

        bool_expr[:must_not] << { term: { wiki_access_level: Featurable::DISABLED } }
        bool_expr[:filter] << { terms: { language: Wiki::MARKUPS.values.pluck(:name) } } # rubocop: disable CodeReuse/ActiveRecord -- It is not an ActiveRecord

        query_hash
      end

      def archived_filter_applicable_on_wiki?(options)
        !options[:include_archived] && options[:search_level] != 'project'
      end
    end
  end
end
