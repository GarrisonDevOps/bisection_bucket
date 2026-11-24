# frozen_string_literal: true

module Types
  module Ai
    class DomainSettingActionEnum < BaseEnum
      graphql_name 'AiDomainSettingAction'
      description 'Action to perform on a domain setting list for AI features.'

      value 'ADD', value: 'add', description: 'Add domains to the list.'
      value 'REMOVE', value: 'remove', description: 'Remove domains from the list.'
    end
  end
end
