# frozen_string_literal: true

class BackfillActiveOnGroups < Elastic::Migration
  include ::Search::Elastic::MigrationBackfillHelper

  batched!
  batch_size 9_000
  throttle_delay 1.minute

  DOCUMENT_TYPE = Group

  private

  def field_name
    :active
  end
end
