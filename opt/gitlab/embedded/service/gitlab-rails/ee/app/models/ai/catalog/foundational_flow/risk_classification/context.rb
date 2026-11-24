# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      module RiskClassification
        module Context
          module_function

          def call(runtime_context:) # rubocop:disable Lint/UnusedMethodArgument -- kept to match validation
            domains = ::Gitlab::Duo::RiskAssessment::Domain.all.map do |domain|
              { "name" => domain.name, "description" => domain.description }
            end

            { "domains" => domains }
          end
        end
      end
    end
  end
end
