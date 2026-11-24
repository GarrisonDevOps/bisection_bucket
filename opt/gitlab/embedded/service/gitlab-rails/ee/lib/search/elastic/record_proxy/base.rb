# frozen_string_literal: true

module Search
  module Elastic
    module RecordProxy
      # Base class for record proxies that enhance records with additional
      # data optimized for elasticsearch indexing.
      #
      # Proxies delegate all method calls to the underlying record while
      # providing the ability to override specific methods with preloaded data.
      class Base < SimpleDelegator
        # Override in subclasses to define enhanced methods
        # This method should be called during proxy creation to set up
        # any additional optimized data access methods
        def enhance_with_data(data)
          data.each do |method_name, value|
            define_singleton_method(method_name) { value }
          end
        end
      end
    end
  end
end
