# frozen_string_literal: true

module Types
  module Vulnerabilities
    class DueDateWildcardIdEnum < BaseEnum
      graphql_name 'VulnerabilityDueDateWildcardId'
      description 'Vulnerability due date wildcard values'

      value 'NONE', 'No due date is assigned.'
      value 'ANY', 'Due date is assigned.'
    end
  end
end
