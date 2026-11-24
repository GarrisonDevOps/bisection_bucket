# frozen_string_literal: true

module Types
  module Snippets
    # Kept to avoid changing the type of existing fields. New fields should use
    # ::Types::BlobViewerType directly
    class BlobViewerType < ::Types::BlobViewerType # rubocop:disable Graphql/AuthorizeTypes
      graphql_name 'SnippetBlobViewer'

      # Replaces the directive inherited from BlobViewerType: only snippet blobs return this type.
      authorize_granular_token parent_authorizes: :read_snippet
    end
  end
end
