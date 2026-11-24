# frozen_string_literal: true

module Types
  module Namespaces
    module MarkdownPaths
      class UserNamespaceMarkdownPathsType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent is already authorized
        graphql_name 'UserNamespaceMarkdownPaths'
        implements ::Types::Namespaces::MarkdownPaths

        authorize_granular_token parent_authorizes: :read_namespace
      end
    end
  end
end
