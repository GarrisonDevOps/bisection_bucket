# frozen_string_literal: true

module Labkit
  module ApplicationSli
    COUNTER_PREFIX = 'gitlab_sli'

    module ClassMethods
      INITIALIZATION_MUTEX = Mutex.new

      def [](name)
        known_slis[name] || initialize_sli(name, [])
      end

      def initialize_sli(name, possible_label_combinations)
        INITIALIZATION_MUTEX.synchronize do
          next known_slis[name] if initialized?(name)

          sli = new(name)
          sli.initialize_counters(possible_label_combinations)
          known_slis[name] = sli
        end
      end

      def initialized?(name)
        known_slis.key?(name) && known_slis[name].initialized?
      end

      private

      def known_slis
        @known_slis ||= {}
      end
    end

    def self.included(mod)
      mod.extend(ClassMethods)
    end

    attr_reader :name

    def initialize(name)
      @name = name
      @initialized_with_combinations = false
    end

    def initialize_counters(possible_label_combinations)
      @initialized_with_combinations = possible_label_combinations.any?
      possible_label_combinations.each do |label_combination|
        total_counter.get(label_combination)
        numerator_counter.get(label_combination)
      end
    end

    def increment(labels:, increment_numerator:)
      total_counter.increment(labels)
      numerator_counter.increment(labels) if increment_numerator
    end

    def initialized?
      @initialized_with_combinations
    end

    private

    def total_counter
      prometheus.counter(counter_name('total'), "Total number of measurements for #{name}")
    end

    def prometheus
      Labkit::Metrics::Client
    end

    autoload :Apdex, "labkit/application_sli/apdex"
    autoload :ErrorRate, "labkit/application_sli/error_rate"
  end
end
