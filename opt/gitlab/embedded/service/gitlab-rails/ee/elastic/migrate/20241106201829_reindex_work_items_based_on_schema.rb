# frozen_string_literal: true

class ReindexWorkItemsBasedOnSchema < Elastic::Migration
  include Search::Elastic::MigrationReindexBasedOnSchemaVersion
  extend ::Gitlab::Utils::Override

  batched!
  batch_size 9_000
  throttle_delay 1.minute

  DOCUMENT_TYPE = WorkItem
  NEW_SCHEMA_VERSION = 24_46

  private

  override :index_name
  def index_name
    Search::Elastic::Types::WorkItem.index_name
  end
end

ReindexWorkItemsBasedOnSchema.prepend ::Search::Elastic::MigrationObsolete
