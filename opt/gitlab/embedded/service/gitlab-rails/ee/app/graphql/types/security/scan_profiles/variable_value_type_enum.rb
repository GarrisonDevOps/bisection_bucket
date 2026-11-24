# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      class VariableValueTypeEnum < BaseEnum
        graphql_name 'SecurityScanProfileVariableValueType'
        description 'Kind of value a scan profile configuration variable takes.'

        value 'BOOLEAN', value: :boolean, description: 'True or false.',
          experiment: { milestone: '19.6' }
        value 'ENUM', value: :enum, description: 'One of the values listed in the variable options.',
          experiment: { milestone: '19.6' }
        value 'INTEGER', value: :integer, description: 'Whole number.',
          experiment: { milestone: '19.6' }
        value 'MULTI_SELECT', value: :multi_select, description: 'Any number of values listed in the variable options.',
          experiment: { milestone: '19.6' }
        value 'STRING', value: :string, description: 'Single string.',
          experiment: { milestone: '19.6' }
        value 'STRING_LIST', value: :string_list, description: 'List of strings.',
          experiment: { milestone: '19.6' }
      end
    end
  end
end
