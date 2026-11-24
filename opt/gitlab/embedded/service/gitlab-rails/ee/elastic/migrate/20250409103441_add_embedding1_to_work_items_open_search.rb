# frozen_string_literal: true

class AddEmbedding1ToWorkItemsOpenSearch < Elastic::Migration
  include ::Search::Elastic::MigrationUpdateMappingsHelper

  skip_if -> { !Search::Elastic::Helper.default.vectors_supported?(:opensearch) }

  def index_name
    work_item_proxy.index_name
  end

  def new_mappings
    { embedding_1: work_item_proxy.opensearch_knn_field }
  end

  private

  def work_item_proxy
    Search::Elastic::Types::WorkItem
  end
end

AddEmbedding1ToWorkItemsOpenSearch.prepend ::Search::Elastic::MigrationObsolete
