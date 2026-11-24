# frozen_string_literal: true

module Types
  module Ci
    module Catalog
      module Resources
        # rubocop: disable Graphql/AuthorizeTypes -- Authorization is handled by VersionType
        class ComponentType < BaseObject
          graphql_name 'CiCatalogResourceComponent'

          field :id, ::Types::GlobalIDType[::Ci::Catalog::Resources::Component], null: false,
            description: 'ID of the component.'

          field :name, GraphQL::Types::String, null: true,
            description: 'Name of the component.'

          field :include_path, GraphQL::Types::String, null: true,
            description: 'Path used to include the component.'

          field :description, GraphQL::Types::String, null: true,
            description: 'Description of the component.'

          field :inputs, [Types::Ci::Inputs::SpecType], null: true,
            description: 'Inputs for the component.'

          field :last_30_day_usage_count, GraphQL::Types::Int, null: true,
            description: 'Number of unique projects that used this version of the component ' \
              'in a pipeline by using `include` in the last 30 days.'

          def description
            object.spec['description']
          end

          def inputs
            ::Ci::Inputs::Builder
              .new(object.ordered_inputs.with_indifferent_access)
              .all_inputs
              .map { |input| input_hash(input) }
          end

          private

          def input_hash(input)
            {
              name: input.name,
              required?: input.required?,
              default: input.default,
              options: (input.options if input.options.is_a?(Array)),
              description: input.description,
              regex: input.regex,
              type: input.type,
              rules: rules_for(input)
            }
          end

          def rules_for(input)
            rules = input.spec['rules']
            return unless rules.is_a?(Array)

            rules.filter_map do |rule|
              next unless rule.is_a?(Hash)

              rule['options'].is_a?(Array) ? rule : rule.except('options')
            end
          end
        end
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
