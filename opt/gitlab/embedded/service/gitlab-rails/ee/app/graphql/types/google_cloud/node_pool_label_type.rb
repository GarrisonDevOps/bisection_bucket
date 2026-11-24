# frozen_string_literal: true

module Types
  module GoogleCloud
    class NodePoolLabelType < BaseInputObject
      graphql_name 'GoogleCloudNodePoolLabel'
      description 'Labels for the Node Pool of a GKE cluster.'

      argument :key, GraphQL::Types::String, description: 'Key of the label.'
      argument :value, GraphQL::Types::String, description: 'Value of the label.'
    end
  end
end
