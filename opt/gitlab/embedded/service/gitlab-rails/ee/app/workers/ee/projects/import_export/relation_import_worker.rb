# frozen_string_literal: true

module EE
  module Projects
    module ImportExport
      module RelationImportWorker
        extend ::Gitlab::Utils::Override

        private

        override :perform_post_import_tasks
        def perform_post_import_tasks
          super

          ::WorkItems::Statuses::BackfillProjectRowsWorker.perform_async(project.id)
        end
      end
    end
  end
end
