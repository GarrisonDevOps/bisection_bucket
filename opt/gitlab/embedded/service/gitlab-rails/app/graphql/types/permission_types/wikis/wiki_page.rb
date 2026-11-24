# frozen_string_literal: true

module Types
  module PermissionTypes
    module Wikis
      class WikiPage < BasePermissionType
        graphql_name 'WikiPagePermissions'

        authorize_granular_token parent_authorizes: :read_wiki

        abilities :read_wiki_page, :create_note, :mark_note_as_internal, :award_emoji
      end
    end
  end
end
