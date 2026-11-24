# frozen_string_literal: true

require 'singleton'
require 'set'

module Labkit
  module Logging
    module FieldValidator
      class Registry
        include Singleton

        attr_reader :offenses

        def initialize
          @mutex = Mutex.new
          @offenses = Set.new
          @offense_keys = Set.new # For O(1) lookup
          @removed_offenses = Set.new
          @baseline_by_callsite = nil
          @resolved_fields = {} # Cache for resolved standard fields
        end

        def record_offense(callsite, lineno, deprecated_field, standard_field, logger_class)
          key = [callsite, deprecated_field, logger_class].freeze

          return if @offense_keys.include?(key)

          @mutex.synchronize do
            next if @offense_keys.include?(key)

            @offense_keys << key
            @offenses << {
              'callsite' => callsite,
              'lineno' => lineno,
              'deprecated_field' => deprecated_field,
              'standard_field' => standard_field,
              'logger_class' => logger_class
            }.freeze

            @removed_offenses.reject! { |r| offense_key(r) == key }
          end
        end

        def check_for_removed_offenses(callsite, fields, logger_class)
          baseline = baseline_by_callsite[[callsite, logger_class]]
          return unless baseline

          @mutex.synchronize do
            baseline.each do |offense|
              key = offense_key(offense)
              next if @offense_keys.include?(key)

              deprecated = offense['deprecated_field']
              standard = resolve_standard_field(offense['standard_field'])

              next unless fields.include?(standard) && fields.exclude?(deprecated)

              @removed_offenses << offense
            end
          end
        end

        # Returns [detected_offenses, new_offenses, removed_offenses]
        def finalize
          @mutex.synchronize do
            baseline_keys = load_baseline.to_set { |b| offense_key(b) }

            new_offenses = @offenses.reject { |o| baseline_keys.include?(offense_key(o)) }

            [@offenses.to_a, new_offenses, @removed_offenses.to_a]
          end
        end

        def clear!
          @mutex.synchronize do
            @offenses.clear
            @offense_keys.clear
            @removed_offenses.clear
            @baseline_by_callsite = nil
            @resolved_fields.clear
          end
        end

        private

        def offense_key(offense)
          [offense['callsite'], offense['deprecated_field'], offense['logger_class']].freeze
        end

        def baseline_by_callsite
          @baseline_by_callsite ||= load_baseline.group_by { |o| [o['callsite'], o['logger_class']] }
        end

        def resolve_standard_field(standard_field)
          # Convert "Labkit::Fields::GL_USER_ID" to actual value "gl.user_id"
          @resolved_fields[standard_field] ||= resolve_labkit_field_constant(standard_field)
        end

        def resolve_labkit_field_constant(standard_field)
          return standard_field unless standard_field.start_with?('Labkit::Fields::')

          const_name = standard_field.delete_prefix('Labkit::Fields::')
          return standard_field unless Labkit::Fields.const_defined?(const_name)

          Labkit::Fields.const_get(const_name)
        end

        def load_baseline
          config = Config.load
          config.fetch('offenses', [])
        end

        def extract_string_keys(data)
          return Set.new unless data.is_a?(Hash)

          data.keys.to_set(&:to_s)
        end
      end
    end
  end
end
