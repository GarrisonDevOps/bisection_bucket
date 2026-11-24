# frozen_string_literal: true

module Labkit
  module ApplicationSli
    class Apdex
      include Labkit::ApplicationSli

      def increment(labels:, success:)
        super(labels: labels, increment_numerator: success)
      end

      private

      def counter_name(suffix)
        :"#{COUNTER_PREFIX}_#{name}_apdex_#{suffix}"
      end

      def numerator_counter
        prometheus.counter(counter_name('success_total'), "Number of successful measurements for #{name}")
      end
    end
  end
end
