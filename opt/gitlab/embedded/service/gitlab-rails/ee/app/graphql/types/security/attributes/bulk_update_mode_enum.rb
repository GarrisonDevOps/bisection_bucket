# frozen_string_literal: true

module Types
  module Security
    module Attributes
      class BulkUpdateModeEnum < Types::BaseEnum
        graphql_name 'SecurityAttributeBulkUpdateMode'
        description 'Mode for bulk updating security attributes'

        value 'ADD', 'Add attributes to projects (keeps existing attributes).'
        value 'REMOVE', 'Remove attributes from projects.'
        value 'REPLACE', 'Replace all existing attributes with the specified attributes.'
      end
    end
  end
end
