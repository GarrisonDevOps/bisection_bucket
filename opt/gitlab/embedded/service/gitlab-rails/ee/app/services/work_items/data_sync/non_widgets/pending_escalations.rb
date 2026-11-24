# frozen_string_literal: true

module WorkItems
  module DataSync
    module NonWidgets
      class PendingEscalations < ::WorkItems::DataSync::Widgets::Base
        # This should go to the post_move_cleanup callback once we implement original item cleanup, but to replicate
        # current behaviour we have in EE::Issues::MoveService, where pending escalations are deleted from
        # original issue, upon move, we will be doing it in `after_save_commit`
        def after_save_commit
          return unless params[:operation] == :move

          work_item.pending_escalations.each_batch(of: BATCH_SIZE) do |pending_escalations_batch|
            pending_escalations_batch.delete_all
          end
        end
      end
    end
  end
end
