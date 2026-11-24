# frozen_string_literal: true

module Types
  module Ci
    module Minutes
      class DeletedNamespaceType < ::Types::BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Resolver auth
        graphql_name 'CiDeletedNamespace'
        description 'Reference to a namespace that no longer exists'

        authorize_granular_token permissions: :read_dedicated_hosted_runner_usage, boundary: :instance,
          boundary_type: :instance, assignable_when: [:admin]

        DeletedNamespace = Struct.new(:raw_id) do
          def to_global_id
            ::Gitlab::GlobalId.build(model_name: ::Namespace.name, id: raw_id)
          end
        end

        field :id, ::Types::GlobalIDType[::Namespace], null: true,
          description: 'ID of the deleted namespace.'
      end
    end
  end
end
