# frozen_string_literal: true

module Types
  module Namespaces
    module LinkPaths
      class UserNamespaceLinksType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent is already authorized
        graphql_name 'UserNamespaceLinks'
        implements ::Types::Namespaces::LinkPaths

        authorize_granular_token parent_authorizes: :read_namespace

        # Do not expose the export email for user namespaces, since exporting work items on this namespace type is not
        # supported
        def user_export_email; end

        def new_trial_path; end
      end
    end
  end
end

::Types::Namespaces::LinkPaths::UserNamespaceLinksType.prepend_mod
