# frozen_string_literal: true

class AddEmbeddingToIssues < Elastic::Migration
  include ::Search::Elastic::MigrationUpdateMappingsHelper

  skip_if -> { !Search::Elastic::Helper.default.vectors_supported?(:elasticsearch) }

  DOCUMENT_TYPE = Issue

  private

  def new_mappings
    {
      embedding: {
        type: 'dense_vector',
        dims: 768,
        similarity: 'dot_product',
        index: true
      },
      embedding_version: {
        type: 'short'
      }
    }
  end
end

AddEmbeddingToIssues.prepend ::Search::Elastic::MigrationObsolete
