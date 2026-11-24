# frozen_string_literal: true

module Gitlab
  module Database
    module Aggregation
      # Shared by the ActiveRecord and ClickHouse filter definitions. Each check is an ActiveModel
      # validator, built once from the `max_size:` and `in:` options given to the definition.
      # They check the values as the request sent them, because a formatter can drop values
      # it does not recognize.
      module FilterValidators
        def initialize(*args, **kwargs)
          super
          @validators = build_validators(max_size: kwargs[:max_size], allowed_values: kwargs[:in])
        end

        def validate_part(part)
          values = Array.wrap(part.raw_values)
          validators.each { |validator| validator.validate_each(part, :base, values) }
        end

        # Read back from the length validator, so the limit is stored in one place.
        def max_size
          length_validator = validators.find { |validator| validator.is_a?(ActiveModel::Validations::LengthValidator) }
          length_validator.options[:maximum] if length_validator
        end

        private

        attr_reader :validators

        def build_validators(max_size:, allowed_values:)
          validators = []

          if max_size
            validators << ActiveModel::Validations::LengthValidator.new(
              attributes: [:raw_values],
              maximum: max_size,
              message: ->(part, data) {
                format(ns_("AggregationEngine|Filter `%{key}` supports at most %{max} value",
                  "AggregationEngine|Filter `%{key}` supports at most %{max} values", data[:count]),
                  key: part.identifier, max: data[:count])
              }
            )
          end

          if allowed_values
            validators << AllowedValuesValidator.new(
              attributes: [:raw_values],
              in: allowed_values,
              # Rails interpolates a Proc message through I18n, so escape `%` in the request values.
              message: ->(part, data) {
                format(s_("AggregationEngine|Invalid values for filter `%{key}`: %{values}"),
                  key: part.identifier, values: data[:values].gsub('%', '%%'))
              }
            )
          end

          validators
        end
      end
    end
  end
end
