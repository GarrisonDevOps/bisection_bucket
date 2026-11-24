# frozen_string_literal: true

module Elastic
  module Latest
    class ApplicationClassProxy < Elasticsearch::Model::Proxy::ClassMethodsProxy
      include ClassProxyUtil
      include Elastic::Latest::Routing
      include Elastic::Latest::QueryContext::Aware

      ADVANCED_QUERY_SYNTAX_REGEX = /[+*"\-|()~\\]/

      def search(query, search_options = {})
        es_options = routing_options(search_options)

        # Counts need to be fast as we load one count per type of document
        # on every page load. Fail early if they are slow since they don't
        # need to be accurate.
        es_options[:timeout] = search_options[:count_only] ? '1s' : '30s'
        es_options[:index] = search_options[:index_name] if search_options[:index_name]

        # Calling elasticsearch-ruby method
        super(query, es_options)
      end

      def es_type
        target.name.underscore
      end

      def es_import(**options)
        transform = ->(r) do
          proxy = r.__elasticsearch__.version(version_namespace)

          { index: { _id: proxy.es_id, data: proxy.as_indexed_json } }.tap do |data|
            data[:index][:routing] = proxy.es_parent if proxy.es_parent
          end
        end

        options[:transform] = transform

        import(options)
      end

      # Should be overridden in *ClassProxy for specific model if data needs to
      # be preloaded by #as_indexed_json method
      def preload_indexing_data(relation)
        relation
      end

      private

      def match_none
        {
          query: { match_none: {} },
          size: 0
        }
      end

      def highlight_options(fields)
        es_fields = fields.map { |field| field.split('^').first }.each_with_object({}) do |field, memo|
          memo[field.to_sym] = {}
        end

        # Adding number_of_fragments: 0 to not split results into snippets.
        # This way controllers can decide how to handle the highlighted data.
        {
          fields: es_fields,
          number_of_fragments: 0,
          pre_tags: [::Elastic::Latest::GitClassProxy::HIGHLIGHT_START_TAG],
          post_tags: [::Elastic::Latest::GitClassProxy::HIGHLIGHT_END_TAG]
        }
      end

      def build_match_phrase_query(options)
        {
          multi_match: {
            _name: context.name(es_type, :multi_match_phrase, :search_terms),
            type: :phrase,
            fields: options[:fields],
            query: options[:query],
            lenient: true
          }
        }
      end

      def build_multi_match_query(options, operator)
        {
          multi_match: {
            _name: context.name(es_type, :multi_match, operator, :search_terms),
            fields: options[:fields],
            query: options[:query],
            operator: operator,
            lenient: true
          }
        }
      end

      def basic_query_hash(fields, query, options = {})
        fields = CustomLanguageAnalyzers.add_custom_analyzers_fields(fields)

        fields = remove_fields_boost(fields) if options[:count_only]

        query_hash =
          if query.present?
            simple_query_string = {
              simple_query_string: {
                _name: context.name(es_type, :match, :search_terms),
                fields: fields,
                query: query,
                lenient: true,
                default_operator: :and
              }
            }

            options[:fields] = fields
            options[:query] = query
            build_query_filter(simple_query_string, options)
          else
            {
              query: {
                bool: {
                  must: { match_all: {} }
                }
              },
              track_scores: true
            }
          end

        if options[:count_only]
          query_hash[:size] = 0
        else
          query_hash[:highlight] = highlight_options(fields)
        end

        query_hash
      end

      def build_query_filter(simple_query_string, options)
        should = []
        must = []

        filter = if options[:no_join_project]
                   []
                 else
                   [
                     {
                       term: {
                         type: {
                           _name: context.name(:doc, :is_a, es_type),
                           value: es_type
                         }
                       }
                     }
                   ]
                 end

        use_match_queries = !query_using_advanced_syntax?(options[:query])

        if options[:count_only] && use_match_queries
          filter << { bool: {
            _name: context.name(:count, es_type, :using_match_queries),
            minimum_should_match: 1,
            should: [
              build_multi_match_query(options, :and),
              build_match_phrase_query(options)
            ]
          } }
        elsif options[:count_only]
          filter << simple_query_string
        elsif use_match_queries
          multi_match_bool = ::Search::Elastic::BoolExpr.new
          multi_match_bool.should << build_multi_match_query(options, :and)
          multi_match_bool.should << build_match_phrase_query(options)
          multi_match_bool.minimum_should_match = 1

          must << { bool: multi_match_bool.to_h }
        else
          must << simple_query_string
        end

        query_hash = {
          query: {
            bool: {
              must: must,
              should: should,
              filter: filter
            }
          }
        }

        query_hash[:query][:bool][:minimum_should_match] = 1 if !should.empty? && use_match_queries

        query_hash
      end

      def query_using_advanced_syntax?(query_string)
        ADVANCED_QUERY_SYNTAX_REGEX.match?(query_string)
      end

      def remove_fields_boost(fields)
        fields.map { |m| m.split('^').first }
      end

      def archived_filter(query_hash)
        archived_false_query = { bool: { filter: { term: { archived: { value: false } } } } }
        archived_missing_query = { bool: { must_not: { exists: { field: 'archived' } } } }
        exclude_archived_query = { bool: { _name: context.name(:non_archived),
                                           should: [archived_false_query, archived_missing_query] } }
        query_hash[:query][:bool] ||= {}
        query_hash[:query][:bool][:filter] ||= []
        query_hash[:query][:bool][:filter] << exclude_archived_query

        query_hash
      end

      # This is a helper method that we are using to add filter conditions
      # in this method we are skipping all blank hashes and we can use it for adding nested filter conditions.
      # `path` is a sequence of key objects (Hash#dig syntax). The value by that path should be an array.
      def add_filter(query_hash, *path)
        filter_result = yield

        return query_hash if filter_result.blank?

        query_hash.dig(*path) << filter_result
        query_hash
      end

      def apply_simple_query_string(name:, fields:, query:, bool_expr:, count_only:)
        path = if count_only
                 fields = remove_fields_boost(fields)
                 :filter
               else
                 :must
               end

        simple_query_string = {
          simple_query_string: {
            _name: name,
            fields: fields,
            query: query,
            default_operator: :and
          }
        }
        add_filter(bool_expr, path) { simple_query_string }
      end
    end
  end
end
