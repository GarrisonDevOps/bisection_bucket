# frozen_string_literal: true

class EnsureCodeCollectionClass < ActiveContext::Migration[1.0]
  milestone '19.2'

  def migrate!
    set_collection_class(collection)
  end

  def collection
    Ai::ActiveContext::Collections::Code
  end
end
