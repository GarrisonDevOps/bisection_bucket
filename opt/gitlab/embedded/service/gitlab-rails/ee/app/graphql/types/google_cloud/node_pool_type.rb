# frozen_string_literal: true

module Types
  module GoogleCloud
    class NodePoolType < BaseInputObject
      graphql_name 'GoogleCloudNodePool'
      description 'Attributes for defining Node Pool in GKE'

      argument :image_type, ::Types::GoogleCloud::ImageType, description: 'Image to use on the pool.'
      argument :labels, [::Types::GoogleCloud::NodePoolLabelType],
        required: false,
        default_value: [],
        replace_null_with_default: true,
        description: 'Labels for the node pool of the runner.'
      argument :machine_type, ::Types::GoogleCloud::MachineTypeType, description: 'Machine type to use.'
      argument :name, GraphQL::Types::String, description: 'Name of the node pool.'
      argument :node_count, GraphQL::Types::Int, description: 'Node count of the pool.'
    end
  end
end
