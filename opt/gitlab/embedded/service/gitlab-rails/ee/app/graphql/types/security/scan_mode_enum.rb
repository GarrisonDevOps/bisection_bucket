# frozen_string_literal: true

module Types
  module Security
    class ScanModeEnum < Types::BaseEnum
      graphql_name 'ScanModeEnum'
      description 'Options for filtering by scan mode.'

      value 'ALL', value: 'all', description: "Return results from all scans."
      value 'FULL', value: 'full', description: "Return results from full scans."
      value 'PARTIAL', value: 'partial', description: "Return results from partial scans."
    end
  end
end
