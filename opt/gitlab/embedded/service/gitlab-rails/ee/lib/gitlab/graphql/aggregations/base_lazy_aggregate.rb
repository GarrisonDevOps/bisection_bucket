# frozen_string_literal: true

# Base class for performing lazy aggregation of data in GraphQL queries.
# This class provides a framework for deferred or lazy-loaded aggregation,
# optimizing query performance by reducing unnecessary database queries.
# Subclasses must define specific behavior for queuing, loading, and resolving objects.
module Gitlab
  module Graphql
    module Aggregations
      class BaseLazyAggregate
        include ::Gitlab::Graphql::Deferred

        attr_reader :query_ctx, :lazy_state

        # Initializes the lazy aggregate with the query context and an object ID.
        # The block is optional and can define additional behavior during execution.
        #
        # @param query_ctx [Hash] the query context (as a Hash)
        # @param object [Object] the object to be lazily loaded from the data source
        # @param block [Proc] an optional block to execute when the object ID is resolved
        def initialize(query_ctx, object, &block)
          raise NameError, "Anonymous classes are not allowed" if self.class.name.nil? || self.class.name.empty?

          @object = object
          @query_ctx = query_ctx
          @block = block

          setup_state

          # Register this object ID for deferred processing
          queued_objects << object
        end

        # Executes the lazy loading logic.
        # Loads all queued objects, processes them, and calls the block if provided.
        #
        # @return [Object] the result of the block or the result method
        def execute
          load_queued_records if queued_objects&.any?

          return @block.call(*block_params) if @block

          result
        end

        # Returns a unique key to identify the state for this object in the query context.
        #
        # @return [Symbol] the key used to store state in the query context
        def state_key
          self.class.name.underscore.to_sym
        end

        private

        # Prepares the state required for lazy loading in the query context.
        # Ensures a shared state object ID is available for the aggregation.
        def setup_state
          @query_ctx[state_key] ||= initial_state
          @lazy_state = query_ctx[state_key]
        end

        # Returns the set of objects queued for loading.
        # Subclasses must implement this to define how objects are queued.
        #
        # @return [Array<Object>] the objects pending resolution
        def queued_objects
          raise NoMethodError
        end

        # Returns the initial state required for the lazy aggregation process.
        # Subclasses must implement this to define their specific aggregation state.
        #
        # @return [Hash] the initial aggregation state
        def initial_state
          raise NoMethodError
        end

        # Resolves the result for the current object ID after all queued objects are loaded.
        # Subclasses must implement this to define how results are derived.
        #
        # @return [Object] the resolved result
        def result
          raise NoMethodError
        end

        # Loads records from the database and resolves queued objects.
        # This method should perform batched queries using all pending object IDs
        # to minimize database calls and prevent N+1 query issues.
        # Subclasses must implement this method to define specific loading logic.
        def load_queued_records
          raise NoMethodError
        end

        # Provides parameters to the block during execution.
        # Subclasses must implement this to define the inputs for the block.
        #
        # @return [Array<Object>] the parameters passed to the block
        def block_params
          raise NoMethodError
        end
      end
    end
  end
end
