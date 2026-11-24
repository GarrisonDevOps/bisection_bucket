# frozen_string_literal: true

module Types
  module Members
    module RoleInterface
      include BaseInterface

      field :id,
        GraphQL::Types::ID,
        null: false,
        description: 'Role ID.'

      field :name,
        GraphQL::Types::String,
        description: 'Role name.'

      field :description,
        GraphQL::Types::String,
        null: true,
        description: 'Role description.'

      field :details_path,
        GraphQL::Types::String,
        experiment: { milestone: '17.4' },
        description: 'URL path to the role details webpage.'
    end
  end
end
