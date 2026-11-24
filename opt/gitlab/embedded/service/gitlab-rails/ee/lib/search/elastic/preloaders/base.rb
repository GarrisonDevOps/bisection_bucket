# frozen_string_literal: true

module Search
  module Elastic
    module Preloaders
      # Base class for elasticsearch preloaders that fetch additional data
      # needed for indexing in batches to avoid N+1 queries.
      #
      # Preloaders are responsible for:
      # 1. Efficiently fetching related data for a batch of records
      # 2. Organizing that data for easy access during proxy creation
      # 3. Providing a consistent interface for data retrieval
      class Base
        def initialize(records)
          @records = Array(records)
        end

        # Preload all necessary data for the records
        def preload
          @preloaded_data ||= safe_preload do
            perform_preload
          end
        end

        # Template method for subclasses to implement their preloading logic
        def perform_preload
          raise NotImplementedError, "#{self.class} must implement #perform_preload"
        end

        # Get preloaded data for a specific record
        def data_for(record)
          preload unless preloaded?
          preloaded_data[record_key(record)]
        end

        # Check if data has been preloaded
        def preloaded?
          !!@preloaded_data
        end

        protected

        attr_reader :records

        # Get the preloaded data hash
        def preloaded_data
          @preloaded_data || {}
        end

        # Generate a key for indexing preloaded data
        # Override in subclasses if a different key is needed
        def record_key(record)
          record[record.class.primary_key]
        end

        # Extract unique identifiers from records for efficient querying
        def record_identifiers
          @record_identifiers ||= records.map { |record| record_key(record) }.uniq
        end

        # Safely execute a block, returning empty hash on error
        # Used to prevent preloader failures from breaking indexing
        def safe_preload
          yield
        rescue StandardError => e
          ::Gitlab::ErrorTracking.track_exception(e, class: self.class.name)
          {}
        end
      end
    end
  end
end
