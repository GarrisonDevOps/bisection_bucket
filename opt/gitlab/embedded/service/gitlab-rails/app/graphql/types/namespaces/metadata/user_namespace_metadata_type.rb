# frozen_string_literal: true

module Types
  module Namespaces
    module Metadata
      class UserNamespaceMetadataType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent is already authorized
        graphql_name 'UserNamespaceMetadata'
        implements ::Types::Namespaces::Metadata

        authorize_granular_token parent_authorizes: :read_namespace

        def issue_repositioning_disabled?
          false
        end

        def show_new_work_item?
          false
        end
      end
    end
  end
end
