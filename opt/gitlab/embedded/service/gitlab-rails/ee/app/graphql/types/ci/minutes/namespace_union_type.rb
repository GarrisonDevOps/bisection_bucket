# frozen_string_literal: true

module Types
  module Ci
    module Minutes
      class NamespaceUnionType < ::GraphQL::Schema::Union
        graphql_name 'NamespaceUnion'
        description 'Represents either a namespace or a reference to a deleted namespace'

        possible_types ::Types::NamespaceType, ::Types::Ci::Minutes::DeletedNamespaceType

        TypeNotSupportedError = Class.new(StandardError)

        def self.resolve_type(object, _context)
          case object
          when ::Namespace
            ::Types::NamespaceType
          when ::Types::Ci::Minutes::DeletedNamespaceType::DeletedNamespace
            ::Types::Ci::Minutes::DeletedNamespaceType
          else
            raise TypeNotSupportedError
          end
        end
      end
    end
  end
end
