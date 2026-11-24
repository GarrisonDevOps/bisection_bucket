# frozen_string_literal: true

module EE
  module Gitlab
    module JiraImport
      module Stage
        module FinishImportWorker
          extend ::Gitlab::Utils::Override

          private

          override :import
          def import(project)
            super

            ::WorkItems::Statuses::BackfillProjectRowsWorker.perform_async(project.id)
          end
        end
      end
    end
  end
end
