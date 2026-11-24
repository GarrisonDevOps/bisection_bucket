# frozen_string_literal: true

module Gitlab
  module Database
    module Aggregation
      class QueryPlan
        # Parameter values of one plan part, validated against the definition's parameter specs.
        class ParameterSet
          include ActiveModel::Validations

          attr_reader :definition

          validate :validate_values
          validate :validate_combinations

          def initialize(definition, configuration)
            @definition = definition
            @configuration = configuration
            @formatted = {}
          end

          # Formatted value, computed once on first read.
          def [](key)
            return @formatted[key] if @formatted.key?(key)

            val = raw_value(key)
            formatter = specs.dig(key, :formatter)

            @formatted[key] = formatter && !val.nil? ? formatter.call(val) : val
          end

          # Raw values of the provided parameters, as passed to definition expressions.
          def expression_params
            specs.keys.each_with_object({}) do |key, params|
              val = raw_value(key)
              params[key] = val if val
            end
          end

          # What the validators read for a parameter: its raw value, already a list when the spec
          # declares `array: true`, and nil when the request leaves it out.
          def read_attribute_for_validation(key)
            raw_value(key)
          end

          private

          def specs
            definition.parameterized? ? definition.parameters : {}
          end

          def raw_value(key)
            definition.instance_parameter(key, @configuration) if definition.parameterized?
          end

          def validate_values
            specs.each do |key, spec|
              rule_validators(key, spec).each { |validator| validator.validate(self) }
            end
          end

          # Built for each set, because the messages name the set's owner.
          def rule_validators(key, spec)
            validators = []

            # An empty list adds no condition, so an optional list must not be empty either.
            if spec[:required] || spec[:array]
              validators << ActiveModel::Validations::PresenceValidator.new(
                attributes: [key],
                allow_nil: !spec[:required],
                message: ->(_set, _data) { message(:required, key) }
              )
            end

            if spec[:max_size]
              validators << ActiveModel::Validations::LengthValidator.new(
                attributes: [key],
                maximum: spec[:max_size],
                message: ->(_set, data) { message(:max_size, key, max: data[:count]) }
              )
            end

            if spec[:in]
              validators << AllowedValuesValidator.new(
                attributes: [key],
                in: spec[:in],
                # Rails interpolates a Proc message through I18n, so escape `%` in the request values.
                message: ->(_set, data) { message(:in, key, values: data[:values].gsub('%', '%%')) }
              )
            end

            validators
          end

          def validate_combinations
            return if errors.any?

            definition.validate_parameters(self)
          end

          def message(rule, key, **placeholders)
            template = case rule
                       when :required
                         s_("AggregationEngine|Parameter `%{param}` of `%{owner}` is required")
                       when :max_size
                         s_("AggregationEngine|Parameter `%{param}` of `%{owner}` can't be longer than %{max}")
                       else # :in
                         s_("AggregationEngine|Invalid values for parameter `%{param}` of `%{owner}`: %{values}")
                       end

            format(template, param: key, owner: definition.identifier, **placeholders)
          end
        end
      end
    end
  end
end
