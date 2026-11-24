# frozen_string_literal: true

module Types
  module Security
    class EditableStateEnum < BaseEnum
      graphql_name 'SecurityCategoryEditableState'
      description 'Editable state for security categories and attributes'

      value 'LOCKED', value: 'locked', description: 'Locked state.'
      value 'EDITABLE_ATTRIBUTES', value: 'editable_attributes', description: 'Editable attributes state.'
      value 'EDITABLE', value: 'editable', description: 'Editable state.'
    end
  end
end
