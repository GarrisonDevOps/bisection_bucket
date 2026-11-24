# frozen_string_literal: true

module Types
  module Security
    class ExclusionTypeEnum < Types::BaseEnum
      graphql_name 'ExclusionTypeEnum'
      description 'Enum for types of exclusion for a security scanner'

      value 'PATH', value: 'path', description: 'File or directory location.'
      value 'REGEX_PATTERN', value: 'regex_pattern', description: 'Regex pattern matching rules.'
      value 'RAW_VALUE', value: 'raw_value', description: 'Raw value to ignore.'
      value 'RULE', value: 'rule', description: 'Scanner rule identifier.'
    end
  end
end
