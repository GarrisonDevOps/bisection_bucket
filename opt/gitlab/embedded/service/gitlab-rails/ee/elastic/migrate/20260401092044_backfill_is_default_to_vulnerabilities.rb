# frozen_string_literal: true

class BackfillIsDefaultToVulnerabilities < Elastic::Migration
  include ::Search::Elastic::MigrationBackfillHelper

  batched!
  batch_size 9_000
  throttle_delay 1.minute

  DOCUMENT_TYPE = Vulnerability

  private

  def field_name
    :is_default
  end
end
