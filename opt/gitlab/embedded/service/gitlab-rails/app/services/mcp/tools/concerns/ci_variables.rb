# frozen_string_literal: true

module Mcp
  module Tools
    module Concerns
      module CiVariables
        extend ActiveSupport::Concern

        private

        def ci_variables
          variables = params[:variables]
          return if variables.blank?

          variables.map do |variable|
            variable = variable.with_indifferent_access

            {
              key: variable[:key],
              value: variable[:value],
              variableType: variable[:variable_type]&.upcase
            }.compact
          end
        end
      end
    end
  end
end
