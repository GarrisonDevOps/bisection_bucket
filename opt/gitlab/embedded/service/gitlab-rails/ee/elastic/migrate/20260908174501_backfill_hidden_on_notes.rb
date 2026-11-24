# frozen_string_literal: true

class BackfillHiddenOnNotes < Elastic::Migration
  include ::Search::Elastic::MigrationBackfillHelper

  batched!
  batch_size 9_000
  throttle_delay 1.minute

  # No `retry_on_failure`, matching all six sibling `MigrationBackfillHelper`
  # backfills. For a `batched!` migration it cannot prevent a stall and is the
  # only thing that can cause one: the `*/5` migration cron re-enters a raised
  # batch on its own, while the option fails the migration -- and every
  # migration after it -- once `previous_attempts` reaches 30, a counter that is
  # never reset by a successful batch.

  DOCUMENT_TYPE = Note

  private

  def field_name
    :hidden
  end
end
