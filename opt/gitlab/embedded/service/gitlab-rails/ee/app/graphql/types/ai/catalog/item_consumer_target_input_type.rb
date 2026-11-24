# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class ItemConsumerTargetInputType < BaseInputObject
        graphql_name 'ItemConsumerTargetInput'

        one_of

        argument :group_id, ::Types::GlobalIDType[::Group],
          required: false,
          description: 'Group in which to configure the item.'

        argument :project_id, ::Types::GlobalIDType[::Project],
          required: false,
          description: 'Project in which to configure the item.'
      end
    end
  end
end
