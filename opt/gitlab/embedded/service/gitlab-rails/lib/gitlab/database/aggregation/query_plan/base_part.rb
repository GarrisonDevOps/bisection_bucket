# frozen_string_literal: true

module Gitlab
  module Database
    module Aggregation
      class QueryPlan
        class BasePart
          include ActiveModel::Validations

          attr_reader :definition, :configuration, :query_plan

          delegate :name, :type, :identifier, to: :definition

          validate :validate_definition_presence
          validate :validate_parameter_set
          validate -> { definition&.validate_part(self) }

          def initialize(definition, configuration, query_plan:)
            @definition = definition
            @configuration = configuration
            @query_plan = query_plan
          end

          def parameters
            @parameters ||= ParameterSet.new(definition, configuration)
          end

          def instance_key
            definition.instance_key(configuration)
          end

          def matches?(reference_config)
            configuration[:identifier] == reference_config[:identifier] &&
              instance_key == definition.instance_key(reference_config)
          end

          private

          def validate_definition_presence
            return if definition

            errors.add(:base, format(s_("AggregationEngine|the specified identifier is not available: '%{identifier}'"),
              identifier: configuration[:identifier]))
          end

          def validate_parameter_set
            return if definition.nil? || parameters.valid?

            # Set errors sit on their parameter key, but every message already names the parameter,
            # so the part takes the message alone rather than one prefixed with the key.
            parameters.errors.each { |error| errors.add(:base, error.message) }
          end
        end
      end
    end
  end
end
