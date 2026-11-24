# frozen_string_literal: true

module Search
  module Elastic
    # Accumulate records and submit to elasticsearch in bulk, respecting limits
    # on request size.
    #
    # Call +process+ to accumulate records in memory, submitting bulk requests
    # when the bulk limits are reached.
    #
    # Once finished, call +flush+. Any errors accumulated earlier will be
    # reported by this call.
    #
    # BulkIndexer is not safe for concurrent use.
    class BulkIndexer
      include ::Elasticsearch::Model::Client::ClassMethods

      RoutingMissingError = Class.new(StandardError)

      ZERO_BYTES_PROCESSED = 0

      attr_reader :logger, :failures

      # body - array of json formatted index operation requests awaiting submission to elasticsearch in bulk
      # body_size_bytes - total size in bytes of each json element in body array
      # failures - array of records that had a failure during submission to elasticsearch
      # logger - set the logger used by instance
      # ref_buffer - records awaiting submission to elasticsearch
      #   cleared if `try_send_bulk` is successful
      #   flushed into `failures` if `try_send_bulk` fails
      def initialize(logger:)
        @body = []
        @body_size_bytes = 0
        @failures = []
        @logger = logger
        @ref_buffer = []
      end

      # Adds or removes a document in elasticsearch, depending on whether the
      # database record it refers to can be found
      def process(ref)
        case ref.operation.to_sym
        when :index
          index(ref)
        when :upsert
          upsert(ref)
        when :delete
          delete(ref)
        else
          raise StandardError, "Operation #{ref.operation} is not supported"
        end
      end

      def flush
        send_bulk.failures
      end

      private

      def reset!
        @body = []
        @body_size_bytes = 0
        @ref_buffer = []
      end

      attr_reader :body, :body_size_bytes, :ref_buffer

      def index(ref)
        submit(ref, index_operation(ref))
      rescue ::Elastic::Latest::DocumentShouldBeDeletedFromIndexError => e
        logger.warn(error_message: e.message, record_id: e.record_id, error_class: e.class)
        delete(ref)
      end

      def upsert(ref)
        submit(ref, upsert_operation(ref))
      rescue ::Elastic::Latest::DocumentShouldBeDeletedFromIndexError => e
        logger.warn(error_message: e.message, record_id: e.record_id, error_class: e.class)
        delete(ref)
      rescue ::Search::Elastic::Reference::ReferenceFailure => error
        logger.error(message: error.message, ref: ref.serialize, klass: ref.klass)
        failures.push(ref)
        ZERO_BYTES_PROCESSED
      end

      def delete(ref, index_name: nil)
        submit(ref, delete_operation(ref, index_name: index_name))
      end

      def bulk_limit_bytes
        Gitlab::CurrentSettings.elasticsearch_max_bulk_size_mb.megabytes
      end

      def submit(ref, ops)
        return ZERO_BYTES_PROCESSED if ops.blank?

        jsons = ops.map(&:to_json)

        calculate_bytesize(jsons).tap do |bytesize|
          # if new ref will exceed the bulk limit, send existing buffer of records
          # when successful, clears `body`, `ref_buffer`, and `body_size_bytes`
          # continue to buffer refs until bulk limit is reached or flush is called
          # any errors encountered are added to `failures`
          send_bulk if will_exceed_bulk_limit?(bytesize)

          ref_buffer << ref
          body.concat(jsons)
          @body_size_bytes += bytesize
        end
      end

      def calculate_bytesize(jsons)
        jsons.reduce(0) do |sum, json|
          sum + json.bytesize + 2 # Account for newlines
        end
      end

      def will_exceed_bulk_limit?(bytesize)
        body_size_bytes + bytesize > bulk_limit_bytes
      end

      def send_bulk
        return self if body.empty?

        failed_refs = try_send_bulk

        logger.info(
          'message' => 'bulk_submitted',
          'meta.indexing.body_size_bytes' => body_size_bytes,
          'meta.indexing.bulk_count' => ref_buffer.count,
          'meta.indexing.errors_count' => failed_refs.count
        )

        failures.push(*failed_refs)

        reset!

        self
      end

      def try_send_bulk
        process_errors(client.bulk(body: body))
      rescue StandardError => err
        # If an exception is raised, treat the entire bulk as failed
        logger.error(message: 'bulk_exception', error_class: err.class.to_s, error_message: err.message)

        ref_buffer
      end

      def process_errors(result)
        return [] unless result['errors']

        out = []

        # Items in the response have the same order as items in the request.
        #
        # Example succces: {"index": {"result": "created", "status": 201}}
        # Example failure: {"index": {"error": {...}, "status": 400}}
        result['items'].each_with_index do |item, i|
          op = item['index'] || item['update'] || item['delete']

          if op.nil? || op['error']
            logger.warn(message: 'bulk_error', item: item)
            out << ref_buffer[i]
          end
        end

        out
      end

      def index_operation(ref)
        build_indexing_operation(ref, :index)
      end

      def upsert_operation(ref)
        build_indexing_operation(ref, :upsert)
      end

      def delete_operation(ref, index_name: nil)
        [{ delete: build_op(ref, index_name: index_name) }]
      end

      def build_op(ref, index_name: nil)
        op = {
          _index: index_name || ref.index_name,
          _type: nil,
          _id: ref.identifier
        }

        op[:routing] = ref.routing if ref.routing

        op
      end

      def track_routing_missing_error(ref)
        message = 'Routing field must be present when using upsert for reference with routing'
        Gitlab::ErrorTracking.track_and_raise_for_dev_exception(RoutingMissingError.new(message), ref: ref.serialize)
      end

      def build_indexing_operation(ref, operation)
        index_json = ref.as_indexed_json

        if index_json.blank?
          message = 'Reference as_indexed_json is blank, removing from the queue'
          logger.warn(message: message, ref: ref.serialize)

          return []
        end

        case operation
        when :index
          [{ index: build_op(ref) }, index_json]
        when :upsert
          track_routing_missing_error(ref) if ref.routing && !index_json.with_indifferent_access.key?('routing')
          [{ update: build_op(ref) }, { doc: index_json, doc_as_upsert: true }]
        end
      end
    end
  end
end
