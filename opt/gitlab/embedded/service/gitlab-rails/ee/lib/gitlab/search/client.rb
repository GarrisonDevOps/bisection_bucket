# frozen_string_literal: true

module Gitlab
  module Search
    class Client
      include ::Elastic::Latest::Routing

      AUTHORIZATION_ERRORS = [
        ::Elasticsearch::Transport::Transport::Errors::Unauthorized,
        ::Elasticsearch::Transport::Transport::Errors::Forbidden,
        ::Elasticsearch::Transport::Transport::Errors::ProxyAuthenticationRequired
      ].compact.freeze

      TIMEOUT_ERRORS = [
        ::Faraday::TimeoutError,
        ::Faraday::RequestTimeoutError,
        ::Elasticsearch::Transport::Transport::Errors::RequestTimeout,
        ::Elasticsearch::Transport::Transport::Errors::GatewayTimeout
      ].compact.freeze

      TRANSPORT_ERRORS = [
        ::Faraday::Error,
        ::Elasticsearch::Transport::Transport::Errors::TooManyRequests,
        ::Elasticsearch::Transport::Transport::Errors::InternalServerError,
        ::Elasticsearch::Transport::Transport::Errors::BadGateway,
        ::Elasticsearch::Transport::Transport::Errors::ServiceUnavailable,
        ::Elasticsearch::Transport::Transport::Errors::HTTPVersionNotSupported
      ].compact.freeze

      DELEGATED_METHODS = %i[
        bulk
        cat
        clear_scroll
        cluster
        count
        delete
        delete_by_query
        get
        index
        indices
        nodes
        reindex
        search
        scroll
        update_by_query
      ].freeze

      delegate(*DELEGATED_METHODS, to: :adapter)

      class AuthorizationError < StandardError
        attr_reader :errors

        def initialize(errors)
          @errors = errors
        end

        def message
          'Search authentication failed. Please check your advanced search configuration.'
        end
      end

      class ConnectionError < StandardError
        attr_reader :errors

        def initialize(errors)
          @errors = errors
        end

        def message
          'Search is currently unavailable. Please try again later.'
        end
      end

      def self.execute_search(...)
        new(adapter: search_adapter).execute_search(...)
      end

      def self.execute_count(...)
        new(adapter: search_adapter).execute_count(...)
      end

      def self.search_adapter
        ::Search::Elastic::Helper.new(operation: :search).client
      end

      def initialize(adapter: nil)
        @adapter = adapter || default_adapter
      end

      def execute_search(query:, options:)
        es_query = routing_options(options).merge(
          timeout: options[:count_only] ? '1s' : '30s',
          index: options[:index_name] || options[:klass].index_name,
          body: query
        )

        yield search_with_timeout_check(es_query)
      end

      def execute_count(query:, options:)
        filtered_query = query.slice(:query) # count only accepts query field in the body

        es_query = routing_options(options).merge(
          index: options[:index_name] || options[:klass].index_name,
          body: filtered_query
        )

        yield count(es_query)
      end

      private

      attr_reader :adapter

      # A `timed_out` body means shards dropped out: `hits.total.value` counts only
      # the shards that answered. Raising matches the Elasticsearch::Model path,
      # whose SearchRequest#execute! override has raised here since 2021.
      def search_with_timeout_check(es_query)
        search(es_query).tap do |response|
          next unless response.respond_to?(:[]) && response['timed_out']

          raise ::Elastic::TimeoutError if ::Feature.enabled?(:search_client_raise_on_timed_out,
            ::Feature.current_request)
        end
      end

      def default_adapter
        # Note: in the future, the default adapter should be changed to whatever
        # adapter is compatible with the version of search engine that is being used
        # in GitLab's application settings.
        ::Search::Elastic::Helper.default.client
      end
    end
  end
end
