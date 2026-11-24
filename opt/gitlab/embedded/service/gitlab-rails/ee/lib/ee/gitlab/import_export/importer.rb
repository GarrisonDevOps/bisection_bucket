# frozen_string_literal: true

module EE
  module Gitlab
    module ImportExport
      module Importer
        extend ::Gitlab::Utils::Override

        # Restorers that run immediately after the repository is restored.
        override :post_repo_restorers
        def post_repo_restorers
          return super unless project.gitlab_custom_project_template_import?

          super + [repository_squash_restorer]
        end

        # Restorers that run at the end of the import process.
        override :final_restorers
        def final_restorers
          return super unless project.gitlab_custom_project_template_import?

          super + [custom_template_restorer]
        end

        private

        def repository_squash_restorer
          ::Gitlab::ImportExport::Project::RepositorySquashRestorer.new(
            project: project,
            shared: shared,
            user: current_user
          )
        end

        def custom_template_restorer
          ::Gitlab::ImportExport::Project::CustomTemplateRestorer.new(
            project: project,
            shared: shared,
            user: current_user
          )
        end
      end
    end
  end
end
