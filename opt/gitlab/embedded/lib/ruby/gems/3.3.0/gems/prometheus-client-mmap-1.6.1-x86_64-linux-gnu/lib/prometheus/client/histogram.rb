require 'prometheus/client/metric'
require 'prometheus/client/uses_value_type'

module Prometheus
  module Client
    # A histogram samples observations (usually things like request durations
    # or response sizes) and counts them in configurable buckets. It also
    # provides a sum of all observed values.
    class Histogram < Metric
      # Value represents the state of a Histogram at a given point.
      class Value < Hash
        include UsesValueType
        attr_accessor :sum, :total, :total_inf

        def initialize(type, name, labels, buckets, buckets_descending)
          @sum = value_object(type, name, "#{name}_sum", labels)
          @total = value_object(type, name, "#{name}_count", labels)
          @total_inf = value_object(type, name, "#{name}_bucket", labels.merge(le: "+Inf"))

          # Buckets are precomputed/frozen at the metric level; values hold
          # references to avoid per-label duplication.
          @buckets, @buckets_descending = buckets, buckets_descending

          @buckets.each do |bucket|
            self[bucket] = value_object(type, name, "#{name}_bucket", labels.merge(le: bucket.to_s))
          end
        end

        def observe(value)
          @total_inf.increment()
          @total.increment()
          @sum.increment(value)

          # Write buckets from largest to smallest so any reader always sees
          # monotonic (cumulative) counts; stop once the observation no longer
          # fits to skip needless increments.
          @buckets_descending.each do |bucket|
            break if value > bucket
            self[bucket].increment()
          end
        end

        def get()
          hash = {}
          @buckets.each do |bucket|
            hash[bucket] = self[bucket].get()
          end
          hash
        end
      end

      # DEFAULT_BUCKETS are the default Histogram buckets. The default buckets
      # are tailored to broadly measure the response time (in seconds) of a
      # network service. (From DefBuckets client_golang)
      DEFAULT_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1,
                         2.5, 5, 10].freeze

      # Offer a way to manually specify buckets
      def initialize(name, docstring, base_labels = {},
                     buckets = DEFAULT_BUCKETS)
        raise ArgumentError, 'Unsorted buckets, typo?' unless sorted? buckets

        # Precompute both orders once per metric. Shared across all label sets
        # to avoid per-value allocation and per-observe reverse calls.
        @buckets = buckets.dup.freeze
        @buckets_descending = @buckets.reverse.freeze

        super(name, docstring, base_labels)
      end

      def type
        :histogram
      end

      def observe(labels, value)
        label_set = label_set_for(labels)
        synchronize { @values[label_set].observe(value) }
      end

      private

      def default(labels)
        # TODO: default function needs to know key of hash info (label names and values)
        Value.new(type, @name, labels, @buckets, @buckets_descending)
      end

      def sorted?(bucket)
        bucket.each_cons(2).all? { |i, j| i <= j }
      end
    end
  end
end
