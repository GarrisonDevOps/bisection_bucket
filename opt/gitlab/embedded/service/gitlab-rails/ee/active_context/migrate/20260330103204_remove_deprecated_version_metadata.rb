# frozen_string_literal: true

class RemoveDeprecatedVersionMetadata < ActiveContext::Migration[1.0]
  milestone '18.11'

  def migrate!
    metadata_to_remove = %w[indexing_embedding_versions search_embedding_version]
    updated_metadata = collection.collection_record.metadata.except(*metadata_to_remove)

    collection.collection_record.update!(metadata: updated_metadata)
  end

  def collection
    Ai::ActiveContext::Collections::Code
  end
end
