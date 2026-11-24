# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module Features
        class Designs < Grape::Entity
          class DesignCollection < Grape::Entity
            # Designs are copied in the background when a work item is moved or cloned
            # (WorkItems::DataSync::Widgets::Designs), and uploads are rejected while the copy is in progress.
            expose :copy_state,
              documentation: {
                type: 'String', example: 'ready', values: %w[ready in_progress error],
                desc: 'State of copying designs into this work item after it was moved or cloned: `ready` if no ' \
                  'copy is running, `in_progress` while designs are being copied, or `error` if the copy failed.'
              },
              expose_nil: true
          end

          expose :design_collection,
            using: ::API::Entities::WorkItems::Features::Designs::DesignCollection,
            documentation: {
              type: 'Entities::WorkItems::Features::Designs::DesignCollection',
              desc: 'Design collection of the work item.'
            },
            expose_nil: true
        end
      end
    end
  end
end
