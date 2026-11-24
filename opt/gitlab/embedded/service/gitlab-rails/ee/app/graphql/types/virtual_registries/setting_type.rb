# frozen_string_literal: true

module Types
  module VirtualRegistries
    class SettingType < ::Types::BaseObject
      graphql_name 'VirtualRegistriesSetting'

      description 'Root group level virtual registries settings'

      authorize :read_virtual_registry_setting

      field :enabled,
        GraphQL::Types::Boolean,
        null: false,
        description: 'Indicates whether virtual registries are enabled for the group.'
    end
  end
end
