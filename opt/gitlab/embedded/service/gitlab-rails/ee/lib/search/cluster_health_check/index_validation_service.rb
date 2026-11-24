# frozen_string_literal: true

module Search
  module ClusterHealthCheck
    class IndexValidationService
      include Gitlab::Loggable
      include Gitlab::Utils::StrongMemoize

      # use text id to reduce risk of collision with existing records
      VALIDATION_RECORD_ID = "index_validation_record"
      DEFAULT_OPERATIONS = [:index, :search].freeze

      def self.execute(...)
        new(...).execute
      end

      def initialize(operations: DEFAULT_OPERATIONS, target_classes: nil, logger: nil)
        @target_classes = target_classes
        @requested_operations = operations
        @logger = logger || ::Gitlab::Elasticsearch::Logger.build
      end

      def execute
        return false unless elasticsearch_indexing_enabled?
        return false unless search_cluster_reachable?

        failures = {}
        operations.each do |operation|
          failures.merge!(perform_operation(operation.to_sym, "#{operation} failed"))
        end

        failures.empty?
      rescue ::Gitlab::Search::Client::ConnectionError, ::Gitlab::Search::Client::AuthorizationError,
        ::Elasticsearch::Transport::Transport::Error => e
        log_error('An error occurred while validating search cluster',
          error_message: e.message,
          error_class: e.class.name)
        false
      end

      private

      attr_reader :logger

      def log_error(message, extra_params = {})
        if structured_logging?
          logger.error(build_structured_payload(message: message, **extra_params))
        else
          logger.error(format_message(message, extra_params))
        end
      end

      def log_warn(message, extra_params = {})
        if structured_logging?
          logger.warn(build_structured_payload(message: message, **extra_params))
        else
          logger.warn(format_message(message, extra_params))
        end
      end

      def format_message(message, extra_params)
        return message if extra_params.empty?

        detail_strings = extra_params.map { |k, v| "#{k}: #{v}" }
        "#{message} (#{detail_strings.join(', ')})"
      end

      def structured_logging?
        logger.is_a?(::Gitlab::JsonLogger)
      end

      def elasticsearch_indexing_enabled?
        return true if ::Gitlab::CurrentSettings.elasticsearch_indexing?

        log_warn('The elasticsearch_indexing setting is disabled')
        false
      end

      def search_cluster_reachable?
        return true if elastic_helper.ping?

        log_warn('The search cluster is unreachable')
        false
      end

      def client
        @client ||= ::Gitlab::Search::Client.new
      end

      def elastic_helper
        @elastic_helper ||= Search::Elastic::Helper.default
      end

      def perform_operation(operation, failure_message)
        result = validate(operation)
        failures = result.reject { |_, success| success }
        failures.each_key do |index_alias|
          log_error(failure_message, index_alias: index_alias)
        end
        failures
      end

      def validate(operation)
        aliases.each_with_object({}) do |alias_name, result_hash|
          unless elastic_helper.alias_exists?(name: alias_name)
            log_error('The alias does not exist', alias_name: alias_name)
            result_hash[alias_name] = false
            next
          end

          index_name = elastic_helper.target_index_name(target: alias_name)
          result_hash[alias_name] = case operation
                                    when :index
                                      index(index_name)
                                    when :search
                                      search(index_name)
                                    end
        end
      end

      def index(index_name)
        result = client.index(
          index: index_name,
          refresh: true,
          id: VALIDATION_RECORD_ID,
          body: {}
        )

        result.dig('_shards', 'failed') == 0
      end

      def search(index_name)
        result = client.search(
          index: index_name,
          size: 0,
          body: {
            query: {
              term: { _id: VALIDATION_RECORD_ID }
            }
          }
        )

        result.dig('hits', 'total', 'value') == 1
      end

      def aliases
        pending_classes = ::Elastic::DataMigrationService.pending_create_index_target_classes
        klasses = target_klasses.reject { |klass| pending_classes.include?(klass) }
        standalone_indices = elastic_helper.standalone_indices_proxies(target_classes: klasses)
        aliases = standalone_indices.map(&:index_name)
        aliases << elastic_helper.target_name if target_klasses&.include?(Repository)
        aliases
      end
      strong_memoize_attr :aliases

      def target_klasses
        allowed_classes = ::Search::Elastic::Helper::INDEXED_CLASSES
        (@target_classes.presence || allowed_classes) & allowed_classes
      end
      strong_memoize_attr :target_klasses

      def operations
        (@requested_operations.presence || DEFAULT_OPERATIONS) & DEFAULT_OPERATIONS
      end
      strong_memoize_attr :operations
    end
  end
end
