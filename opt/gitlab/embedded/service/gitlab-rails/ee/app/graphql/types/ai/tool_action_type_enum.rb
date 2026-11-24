# frozen_string_literal: true

module Types
  module Ai
    class ToolActionTypeEnum < BaseEnum
      graphql_name 'AiToolActionType'
      description 'Action type categorisation for an AI tool'

      value 'READ', value: :read, description: 'Tool performs read-only operations.'
      value 'WRITE', value: :write, description: 'Tool performs write operations.'
      value 'DESTROY', value: :destroy, description: 'Tool performs destructive operations.'
    end
  end
end
