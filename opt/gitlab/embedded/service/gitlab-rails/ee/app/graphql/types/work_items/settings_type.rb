# frozen_string_literal: true

module Types
  module WorkItems
    class SettingsType < BaseObject
      graphql_name 'WorkItemSettings'
      description 'Work item settings for a namespace.'

      authorize :read_work_item_setting

      field :customizable_type_visibility, GraphQL::Types::Boolean,
        null: false,
        description: 'Whether namespace admins can configure per-type work item visibility.'
    end
  end
end
