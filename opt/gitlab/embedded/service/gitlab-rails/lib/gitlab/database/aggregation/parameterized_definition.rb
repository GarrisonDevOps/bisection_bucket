# frozen_string_literal: true

module Gitlab
  module Database
    module Aggregation
      module ParameterizedDefinition
        extend ActiveSupport::Concern

        attr_reader :parameters

        def initialize(*args, parameters: {}, **kwargs)
          super

          @parameters = parameters || {}
        end

        def instance_key(configuration)
          return super unless parameterized? && configuration[:parameters].present?

          parameters_postfix = parameters.keys.filter_map do |p_key|
            val = instance_parameter(p_key, configuration)
            next unless val

            val = val.join('_') if val.is_a?(Array)
            # When several parameters are declared, prefix each value with its
            # parameter name so partially provided combinations cannot collide
            # (e.g. `{ bar: '42' }` vs `{ baz: '42' }`).
            parameters.size > 1 ? "#{p_key}_#{val}" : val
          end.join('_')

          unless /\A\w+\z/.match?(parameters_postfix)
            parameters_postfix = OpenSSL::Digest::SHA256.hexdigest(parameters_postfix)[0...5]
          end

          "#{super}_#{parameters_postfix}"
        end

        # Raw request value of one parameter. Wrapped into an Array when the spec declares `array: true`,
        # without duplicates: they add nothing to the query, so `[1, 1, 2]` and `[1, 2]` share an instance key.
        def instance_parameter(param_identifier, configuration)
          return unless parameters[param_identifier]

          val = configuration.dig(:parameters, param_identifier)
          # `false` is a real value, for example a boolean parameter.
          return if val.nil?

          parameters.dig(param_identifier, :array) ? Array.wrap(val).uniq : val
        end

        def parameterized?
          parameters.present?
        end
      end
    end
  end
end
