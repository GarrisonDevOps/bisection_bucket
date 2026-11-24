# frozen_string_literal: true

module Types
  module PermissionTypes
    class Snippet < BasePermissionType
      graphql_name 'SnippetPermissions'

      authorize_granular_token parent_authorizes: :read_snippet

      abilities :create_note, :award_emoji

      permission_field :read_snippet, method: :can_read_snippet?
      permission_field :update_snippet, method: :can_update_snippet?
      permission_field :admin_snippet,
        method: :can_delete_snippet?,
        description: 'If `true`, the user can delete this snippet. Returns the same value as `deleteSnippet`.'
      permission_field :delete_snippet, method: :can_delete_snippet?
      permission_field :report_snippet, method: :can_report_as_spam?
    end
  end
end
