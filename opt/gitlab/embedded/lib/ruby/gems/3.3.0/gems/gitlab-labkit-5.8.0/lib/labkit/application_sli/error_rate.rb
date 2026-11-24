# frozen_string_literal: true

module Labkit
  module ApplicationSli
    class ErrorRate
      include Labkit::ApplicationSli

      def increment(labels:, error:)
        super(labels: labels, increment_numerator: error)
      end

      private

      def counter_name(suffix)
        :"#{COUNTER_PREFIX}_#{name}_#{suffix}"
      end

      def numerator_counter
        prometheus.counter(counter_name('error_total'), "Number of error measurements for #{name}")
      end
    end
  end
end
