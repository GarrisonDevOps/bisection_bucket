# frozen_string_literal: true

module Types
  module Security
    class ExclusionScannerEnum < Types::BaseEnum
      graphql_name 'ExclusionScannerEnum'
      description 'Enum for the security scanners used with exclusions'

      value 'SECRET_PUSH_PROTECTION', value: 'secret_push_protection', description: 'Secret push protection.'
    end
  end
end
