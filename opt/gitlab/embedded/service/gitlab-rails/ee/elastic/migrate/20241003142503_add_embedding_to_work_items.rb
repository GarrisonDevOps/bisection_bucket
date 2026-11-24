# frozen_string_literal: true

class AddEmbeddingToWorkItems < Elastic::Migration
  include ::Search::Elastic::MigrationUpdateMappingsHelper

  skip_if -> { !elasticsearch_8_plus? }

  def index_name
    work_item_proxy.index_name
  end

  def new_mappings
    work_item_proxy.elasticsearch_8_plus_mappings.merge({ routing: { type: 'text' } })
  end

  private

  def elasticsearch_8_plus?
    helper.vectors_supported?(:elasticsearch)
  end

  def helper
    @helper ||= Search::Elastic::Helper.default
  end

  def work_item_proxy
    Search::Elastic::Types::WorkItem
  end
end

AddEmbeddingToWorkItems.prepend ::Search::Elastic::MigrationObsolete
