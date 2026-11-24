# frozen_string_literal: true

module EE
  module Import
    module Offline
      module Imports
        module Groups
          module Stage
            extend ::Gitlab::Utils::Override

            private

            def ee_config
              {
                iterations_cadences: {
                  pipeline: ::BulkImports::Groups::Pipelines::IterationsCadencesPipeline,
                  stage: 1
                },
                epics: {
                  pipeline: ::BulkImports::Groups::Pipelines::EpicsPipeline,
                  stage: 2
                },
                epic_boards: {
                  pipeline: ::BulkImports::Groups::Pipelines::EpicBoardsPipeline,
                  stage: 2
                }
              }
            end

            override :config
            def config
              bulk_import.source_enterprise ? super.deep_merge(ee_config) : super
            end
          end
        end
      end
    end
  end
end
