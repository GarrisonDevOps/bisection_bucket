# frozen_string_literal: true

module WorkItems
  module DataSync
    module Widgets
      class DecisionLog < Base
        # Decisions are not copied on move/clone yet. Follow-up planned to
        # copy them with provenance links (resolving_note_id, discussion_id)
        # remapped, since they reference source-side notes and threads.
        def after_save_commit; end

        def post_move_cleanup
          work_item.decisions.each_batch(of: BATCH_SIZE) do |batch|
            # Options are removed via the DB-level ON DELETE CASCADE
            batch.delete_all
          end
        end
      end
    end
  end
end
