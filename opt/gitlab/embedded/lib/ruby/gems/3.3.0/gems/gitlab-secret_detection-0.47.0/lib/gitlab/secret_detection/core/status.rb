# frozen_string_literal: true

module Gitlab
  module SecretDetection
    module Core
      # All the possible statuses emitted by the scan operation
      class Status
        # These values must stay in-sync with the GRPC::ScanResponse::Status values
        UNSPECIFIED = 0 # to match the GRPC::Status values
        FOUND = 1 # When scan operation completes with one or more findings
        FOUND_WITH_ERRORS = 2 # When scan operation completes with one or more findings along with some errors
        SCAN_TIMEOUT = 3 # When the scan operation runs beyond given time out
        PAYLOAD_TIMEOUT = 4 # When the scan operation on a payload runs beyond given time out
        SCAN_ERROR = 5 # When the scan operation fails due to regex error
        INPUT_ERROR = 6 # When the scan operation fails due to invalid input
        NOT_FOUND = 7 # When scan operation completes with zero findings
        AUTH_ERROR = 8 # When authentication fails

        # Maps values to constants
        @values_map = {}

        # Using class instance variables and singleton methods
        class << self
          attr_reader :values_map

          # Register constants and their values in the map
          def const_set(name, value)
            const = super
            @values_map[value] = name
            const
          end

          # Look up a constant by its value
          def find_by_value(value)
            const_name = @values_map[value]
            const_name ? const_get(const_name) : nil
          end

          # Get the name of a constant by its value
          def name_by_value(value)
            @values_map[value]
          end
        end

        # Initialize the values map with existing constants
        constants.each do |const_name|
          const_value = const_get(const_name)
          @values_map[const_value] = const_name
        end
      end
    end
  end
end
