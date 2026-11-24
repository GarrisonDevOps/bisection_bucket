# frozen_string_literal: true

module Search
  module Elastic
    class ResponseMapper
      def initialize(response, options = {})
        @response = response.with_indifferent_access
        @options = options
      end

      def aggregations
        response['aggregations']
      end

      def records
        preload_method = options[:preload_method]
        klass = options[:klass]
        sql_records = klass.id_in(ids)
        sql_records = sql_records.preload_search_data if sql_records.respond_to?(:preload_search_data)
        sql_records = sql_records.preload(*options[:preloads]) if options[:preloads].present? # rubocop:disable CodeReuse/ActiveRecord -- This is an abstraction
        sql_records = sql_records.public_send(preload_method) if preload_method # rubocop:disable GitlabSecurity/PublicSend -- needed for generic preload method
        # sorted in memory because database sort is not faster due to querying by id only
        # and the records will always be a small set of data (< 100 records)
        sql_records.sort_by { |record| results.index { |hit| hit[:_source][primary_key].to_s == record.id.to_s } }
      end

      def highlight_map
        results.to_h { |x| [x['_source']['id'], x['highlight']] }
      end

      # hits.total counts documents, not collapse groups, so this over-reports for any query
      # using collapse, whichever caller reads it. A row count under collapse would need a
      # cardinality aggregation instead.
      def total_count
        response['hits']['total']['value']
      end

      def paginated_array
        page = options[:page]
        per_page = options[:per_page]

        Kaminari.paginate_array(
          records.to_a,
          total_count: total_count,
          limit: per_page,
          offset: per_page * (page - 1)
        )
      end

      def failed?
        error.present?
      end

      def error
        response['error']
      end

      def error_type
        response.dig('error', 'type')
      end

      def results
        @results ||= response.dig('hits', 'hits')
      end

      private

      attr_reader :options, :response

      def ids
        # the _source: id will always contain an integer
        @ids ||= results.map { |result| result[:_source][primary_key] }
      end

      def primary_key
        options[:primary_key] || :id
      end
    end
  end
end
