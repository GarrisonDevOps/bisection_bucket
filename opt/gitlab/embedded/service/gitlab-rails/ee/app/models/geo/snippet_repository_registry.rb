# frozen_string_literal: true

module Geo
  class SnippetRepositoryRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry

    belongs_to :snippet_repository, class_name: 'SnippetRepository'

    def self.model_class
      ::SnippetRepository
    end

    def self.model_foreign_key
      :snippet_repository_id
    end

    def self.model_updated_scope(ids)
      model_class.where(snippet_id: ids).joins(:snippet)
        .select('snippet_repositories.*, snippets.updated_at AS updated_at')
    end
  end
end
