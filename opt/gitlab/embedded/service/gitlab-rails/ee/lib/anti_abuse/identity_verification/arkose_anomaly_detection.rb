# frozen_string_literal: true

module AntiAbuse
  module IdentityVerification
    module ArkoseAnomalyDetection
      extend self

      ZSCORE_NEGATIVE_THRESHOLD = -3.0

      Decision = Struct.new(:anomalous, :reason, keyword_init: true)

      def decide(current_value:, baseline_values:)
        mean_value = mean(baseline_values)
        stddev_value = stddev(baseline_values, mean_value)

        z = zscore(current_value, mean_value, stddev_value)
        if z <= ZSCORE_NEGATIVE_THRESHOLD
          Decision.new(anomalous: true,
            reason: format('zscore=%.2f mean=%.2f std=%.2f current=%.2f', z, mean_value, stddev_value, current_value))
        else
          Decision.new(anomalous: false, reason: format('zscore_ok=%.2f', z))
        end
      end

      private

      def mean(values)
        return 0.0 if values.empty?

        values.sum(0.0) / values.size
      end

      def variance(values, precomputed_mean = nil)
        return 0.0 if values.size < 2

        m = precomputed_mean || mean(values)
        sum = values.sum(0.0) { |v| (v - m)**2 }
        sum / (values.size - 1)
      end

      def stddev(values, precomputed_mean = nil)
        Math.sqrt([variance(values, precomputed_mean), 0.0].max)
      end

      def zscore(current_value, baseline_mean, baseline_stddev)
        return 0.0 if baseline_stddev.to_f == 0

        (current_value - baseline_mean) / baseline_stddev
      end
    end
  end
end
