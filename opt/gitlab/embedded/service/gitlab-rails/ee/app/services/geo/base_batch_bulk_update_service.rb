# frozen_string_literal: true

module Geo
  # Base service that batches over all records associated with a given class.
  # Subclasses need to implement `attributes_to_update`, `update_scope` and `class_to_update` to define on
  # which attribute and subset of data the update applies to, and `worker` to define which worker is responsible
  # for running the background job async.
  # The service takes as arguments a class_name, which is the name of the class which records (or related records)
  # we want to update, and some params which is a hash used to filter through the records to update.
  class BaseBatchBulkUpdateService
    include ::Gitlab::Geo::LogHelpers
    include ::Gitlab::Utils::StrongMemoize

    TIME_LIMIT = 20.seconds
    BATCH_SIZE = 1_000
    PERFORM_IN = 10.seconds

    def initialize(class_name, params)
      @class_name = class_name
      @serialized_worker_params = params.deep_stringify_keys
      @params = params.with_indifferent_access
    end

    def async_execute
      return error_response("No table found from #{class_name}", job_status: :failed) unless model_class

      worker.perform_async(class_name, serialized_worker_params)

      ServiceResponse.success(message: 'Batch update job has been successfully enqueued.',
        payload: { status: :pending })
    end

    def execute
      runtime_limiter = Gitlab::Metrics::RuntimeLimiter.new(TIME_LIMIT)
      status = :completed
      message = 'All records have been successfully updated.'

      records_to_update.each_batch(of: BATCH_SIZE) do |relation|
        last_record = relation.last
        relation.update_all(attributes_to_update)
        push_cursor(record_id(last_record))

        # rubocop:disable Style/Next -- The limit being reached, we break from the loop
        if runtime_limiter.over_time?
          status = :limit_reached
          message = "#{TIME_LIMIT} seconds limit reached on #{class_to_update.name} update. \
                     A new job will be re-enqueued in #{PERFORM_IN} seconds to continue processing the records."

          worker.perform_in(PERFORM_IN, class_name, serialized_worker_params)
          break
        end
        # rubocop:enable Style/Next
      end

      return delete_redis_key_and_return_success(message) if status == :completed

      error_response(message, job_status: status)
    end

    private

    attr_reader :params, :serialized_worker_params, :class_name

    def attributes_to_update
      raise NotImplementedError, "#{self.class} should implement #{__method__}"
    end

    # The specific scope to be applied to the relation in order to find which records need updating
    def update_scope
      raise NotImplementedError, "#{self.class} should implement #{__method__}"
    end

    def class_to_update
      raise NotImplementedError, "#{self.class} should implement #{__method__}"
    end

    def worker
      raise NotImplementedError, "#{self.class} should implement #{__method__}"
    end

    def model_class
      class_name.constantize
    rescue NameError
      message = "Cannot find a class for #{class_name}"
      e = NotImplementedError.new(message)

      log_error(message, e, class_name:)

      raise e
    end

    def records_to_update
      pk = class_to_update.primary_key
      return update_scope.after_cursor(load_cursor) unless pk.is_a?(Array)

      order_attributes = pk.map do |attribute_name|
        Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
          attribute_name: attribute_name,
          order_expression: class_to_update.arel_table[attribute_name.to_sym].asc,
          nullable: :not_nullable
        )
      end

      # keyset pagination generates UNION queries
      class_to_update.include(FromUnion) unless class_to_update.include?(FromUnion)

      Gitlab::Pagination::Keyset::Iterator.new(scope: update_scope.keyset_order(order_attributes), cursor: load_cursor)
    end

    def load_cursor
      raw_key = Gitlab::Redis::SharedState.with do |redis|
        redis.get(redis_key)
      end

      Gitlab::Json::SafeParser.parse(raw_key) if raw_key
    end

    def push_cursor(pk_value)
      Gitlab::Redis::SharedState.with do |redis|
        redis.set(redis_key, Gitlab::Json.dump(pk_value))
      end
    end

    def redis_key
      "geo:#{class_to_update.table_name}:#{params_hash}:#{self.class.name.demodulize.underscore}_cursor"
    end

    def params_hash
      @params_hash ||= Base64.urlsafe_encode64(Gitlab::Json.dump(serialized_worker_params))
    end

    def record_id(record)
      record.slice(*record.class.primary_key).values
    end

    def delete_redis_key_and_return_success(message)
      log_info(message)

      Gitlab::Redis::SharedState.with do |redis|
        redis.del(redis_key)
      end

      ServiceResponse.success(message: message, payload: { status: :completed })
    end

    def error_response(message, job_status:)
      log_error(message)

      ServiceResponse.error(message: message, payload: { status: job_status })
    end
  end
end
