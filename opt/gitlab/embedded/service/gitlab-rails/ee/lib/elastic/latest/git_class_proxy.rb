# frozen_string_literal: true

module Elastic
  module Latest
    module GitClassProxy
      extend ::Gitlab::Utils::Override
      SHA_REGEX = /\A[0-9a-f]{5,40}\z/i
      HIGHLIGHT_START_TAG = 'gitlabelasticsearch→'
      HIGHLIGHT_END_TAG = '←gitlabelasticsearch'
      MAX_LANGUAGES = 100

      def elastic_search(query, type:, page: 1, per: 20, options: {})
        case type
        when 'commit'
          commit_options = options.merge(features: 'repository', scope: type)
          { commits: search_commit(query, page: page, per: per, options: commit_options) }
        when 'blob'
          blob_options = options.merge(features: 'repository', scope: type)
          { blobs: search_blob(query, type: type, page: page, per: per, options: blob_options) }
        end
      end

      # @return [Kaminari::PaginatableArray]
      def elastic_search_as_found_blob(query, page: 1, per: 20, options: {}, preload_method: nil)
        # Highlight is required for parse_search_result to locate relevant line
        options = options.merge(highlight: true)

        elastic_search_and_wrap(query, type: es_type, page: page, per: per, options: options,
          preload_method: preload_method) do |result, container|
          ::Gitlab::Elastic::SearchResults.parse_search_result(result, container, options)
        end
      end

      def blob_aggregations(query, options)
        blob_options = options.merge(features: 'repository', aggregation: true, scope: 'blob')
        query_hash, options = blob_query(query, options: blob_options)
        results = search(query_hash, options)

        ::Gitlab::Search::AggregationParser.call(results.response.aggregations)
      end

      private

      def options_filter_context(type, options)
        repository_ids = [options[:repository_id]].flatten
        languages = [options[:language]].flatten

        filters = []

        if repository_ids.any?
          filters << {
            terms: {
              _name: context.name(type, :related, :repositories),
              options[:project_id_field] || "#{type}.rid" => repository_ids
            }
          }
        end

        if languages.any? && type == :blob && (!options[:count_only] || options[:aggregation])
          filters << {
            terms: {
              _name: context.name(type, :match, :languages),
              "#{type}.language" => languages
            }
          }
        end

        filters << options[:additional_filter] if options[:additional_filter]

        { filter: filters }
      end

      # rubocop:disable Metrics/AbcSize
      def search_commit(query, page: 1, per: 20, options: {})
        fields = %w[message^10 sha^5 author.name^2 author.email^2 committer.name committer.email]
        query_with_prefix = query.split(/\s+/).map { |s| s.gsub(SHA_REGEX) { |sha| "#{sha}*" } }.join(' ')

        bool_expr = ::Search::Elastic::BoolExpr.new

        options[:index_name] = Elastic::Latest::CommitConfig.index_name
        options[:project_id_field] = 'rid'

        query_hash = {
          query: { bool: bool_expr },
          size: (options[:count_only] ? 0 : per),
          from: per * (page - 1),
          sort: [:_score]
        }

        query_hash = ::Search::Elastic::Filters.by_search_level_and_membership(query_hash: query_hash, options: options)

        if archived_filter_applicable_for_commit_search?(options)
          query_hash = context.name(:archived) { archived_filter(query_hash) }
        end

        bool_expr = apply_simple_query_string(
          name: context.name(:commit, :match, :search_terms),
          fields: fields,
          query: query_with_prefix,
          bool_expr: bool_expr,
          count_only: options[:count_only]
        )

        # add the document type filter
        bool_expr[:filter] << {
          term: {
            type: {
              _name: context.name(:doc, :is_a, :commit),
              value: 'commit'
            }
          }
        }

        # add filters extracted from the options
        options_filter_context = options_filter_context(:commit, options)
        bool_expr[:filter] += options_filter_context[:filter] if options_filter_context[:filter].any?

        options[:order] = :default if options[:order].blank?

        if options[:highlight] && !options[:count_only]
          es_fields = fields.map { |field| field.split('^').first }.each_with_object({}) do |f, memo|
            memo[f.to_sym] = {}
          end

          query_hash[:highlight] = {
            pre_tags: [HIGHLIGHT_START_TAG],
            post_tags: [HIGHLIGHT_END_TAG],
            fields: es_fields
          }
        end

        res = search(query_hash, options)
        {
          results: res.results,
          total_count: res.size
        }
      end

      def archived_filter_applicable_for_commit_search?(options)
        !options[:include_archived] && options[:search_level] != 'project'
      end

      def search_blob(query, type: 'blob', page: 1, per: 20, options: {})
        query_hash, options = blob_query(query, type: type, page: page, per: per, options: options)
        res = search(query_hash, options)

        {
          results: res.results,
          total_count: res.size
        }
      end

      # Wrap returned results into GitLab model objects and paginate
      #
      # @return [Kaminari::PaginatableArray]
      def elastic_search_and_wrap(query, type:, page: 1, per: 20, options: {}, preload_method: nil, &blk)
        response = elastic_search(
          query,
          type: type,
          page: page,
          per: per,
          options: options
        )[type.pluralize.to_sym][:results]

        items, total_count = yield_each_search_result(response, type, preload_method, &blk)

        # Before "map" we had a paginated array so we need to recover it
        offset = per * ((page || 1) - 1)
        Kaminari.paginate_array(items, total_count: total_count, limit: per, offset: offset)
      end

      def yield_each_search_result(response, type, preload_method)
        group_ids = group_ids_from_wiki_response(type, response)
        group_containers = Group.with_route.id_in(group_ids).includes(:deletion_schedule) # rubocop: disable CodeReuse/ActiveRecord
        project_ids = response.map { |result| project_id_for_commit_or_blob(result, type) }.uniq
        # Avoid one SELECT per result by loading all projects into a hash
        project_containers = Project.with_route.id_in(project_ids)
        project_containers = project_containers.public_send(preload_method) if preload_method # rubocop:disable GitlabSecurity/PublicSend
        containers = project_containers + group_containers
        containers = containers.index_by { |container| "#{container.class.name.downcase}_#{container.id}" }
        total_count = response.total_count

        items = response.map do |result|
          container = get_container_from_containers_hash(type, result, containers)

          if container.nil? || container.deletion_in_progress_or_scheduled_in_hierarchy_chain?
            total_count -= 1
            next
          end

          yield(result, container)
        end

        # Remove results for deleted projects
        items.compact!

        [items, total_count]
      end

      def group_ids_from_wiki_response(type, response)
        return unless type.eql?('wiki_blob')

        response.map { |result| group_id_for_wiki_blob(result) }
      end

      def get_container_from_containers_hash(type, result, containers)
        if group_level_wiki_result?(result)
          group_id = group_id_for_wiki_blob(result)
          containers["group_#{group_id}"]
        else
          project_id = project_id_for_commit_or_blob(result, type)
          containers["project_#{project_id}"]
        end
      end

      def group_level_wiki_result?(result)
        result['_source']['type'].eql?('wiki_blob') && result['_source']['rid'].match(/wiki_group_\d+/)
      end

      # Indexed commit does not include project_id
      def project_id_for_commit_or_blob(result, type)
        (result.dig('_source', 'project_id') || result.dig('_source', type, 'rid') || result.dig('_source', 'rid')).to_i
      end

      def group_id_for_wiki_blob(result)
        result.dig('_source', 'group_id')
      end

      # rubocop:disable Metrics/PerceivedComplexity
      # rubocop:disable Metrics/CyclomaticComplexity
      def blob_query(query, type: 'blob', page: 1, per: 20, options: {})
        aggregation = options[:aggregation]
        count_only = options[:count_only]

        query = ::Gitlab::Search::Query.new(query) do
          filter :filename, field: :file_name
          filter :path, parser: ->(input) { "#{input.downcase}*" }
          filter :extension,
            field: 'file_name.reverse',
            type: :prefix,
            parser: ->(input) { "#{input.downcase.reverse}." }
          filter :blob, field: :oid
        end

        bool_expr = ::Search::Elastic::BoolExpr.new
        count_or_aggregation_query = count_only || aggregation
        query_hash = {
          query: { bool: bool_expr },
          size: (count_or_aggregation_query ? 0 : per)
        }

        unless aggregation
          query_hash[:from] = per * (page - 1)
          query_hash[:sort] = [:_score]
        end

        fields = %w[blob.content blob.file_name blob.path]

        bool_expr = apply_simple_query_string(
          name: context.name(:blob, :match, :search_terms),
          query: query.term,
          fields: fields,
          bool_expr: bool_expr,
          count_only: options[:count_only]
        )

        query_hash = ::Search::Elastic::Filters.by_search_level_and_membership(query_hash: query_hash, options: options)

        # add the document type filter
        bool_expr[:filter] << {
          term: {
            type: {
              _name: context.name(:doc, :is_a, type),
              value: type
            }
          }
        }

        # add filters extracted from the query
        query_filter_context = query.elasticsearch_filter_context(:blob)
        bool_expr[:filter] += query_filter_context[:filter] if query_filter_context[:filter].any?
        bool_expr[:must_not] += query_filter_context[:must_not] if query_filter_context[:must_not].any?

        # add filters extracted from the `options`
        options[:project_id_field] = 'blob.rid'
        options_filter_context = options_filter_context(:blob, options)
        bool_expr[:filter] += options_filter_context[:filter] if options_filter_context[:filter].any?
        options[:order] = :default if options[:order].blank? && !aggregation

        if options[:highlight] && !count_or_aggregation_query
          # Highlighted text fragments do not work well for code as we want to show a few whole lines of code.
          # Set number_of_fragments to 0 to get the whole content to determine the exact line number that was
          # highlighted.
          query_hash[:highlight] = {
            pre_tags: [HIGHLIGHT_START_TAG],
            post_tags: [HIGHLIGHT_END_TAG],
            number_of_fragments: 0,
            fields: {
              "blob.content" => {},
              "blob.file_name" => {}
            }
          }
        end

        if type == 'blob' && aggregation
          query_hash[:aggs] = {
            language: {
              terms: {
                field: 'blob.language',
                size: MAX_LANGUAGES
              }
            }
          }
        end

        if type == 'blob' && archived_filter_applicable_for_blob_search?(options)
          query_hash = archived_filter(query_hash)
        end

        [query_hash, options]
      end
      # rubocop:enable Metrics/AbcSize
      # rubocop:enable Metrics/PerceivedComplexity
      # rubocop:enable Metrics/CyclomaticComplexity

      def archived_filter_applicable_for_blob_search?(options)
        !options[:include_archived] && options[:search_level] != 'project'
      end
    end
  end
end
