# frozen_string_literal: true

module Types
  module Sbom
    class ReachabilityEnum < BaseEnum
      graphql_name 'ReachabilityType'
      description 'Dependency reachability status'

      value 'UNKNOWN', value: 'unknown', description: "Dependency reachability status is not available."
      value 'IN_USE', value: 'in_use', description: "Dependency is imported and in use."
      value 'NOT_FOUND', value: 'not_found', description: "Dependency is not in use."

      def self.coerce_result(value, _ctx)
        value.to_s.upcase
      end
    end
  end
end
