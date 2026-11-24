# frozen_string_literal: true

module EE
  module WorkItems
    module DataSync
      module Widgets
        module Labels
          extend ::Gitlab::Utils::Override

          override :post_move_cleanup
          def post_move_cleanup
            batch_size = ::WorkItems::DataSync::Widgets::Base::BATCH_SIZE

            work_item.label_links.each_batch(of: batch_size) do |label_links_batch|
              targets = [work_item, work_item.sync_object].compact
              label_links_batch.by_targets(targets).delete_all
            end
          end
        end
      end
    end
  end
end
