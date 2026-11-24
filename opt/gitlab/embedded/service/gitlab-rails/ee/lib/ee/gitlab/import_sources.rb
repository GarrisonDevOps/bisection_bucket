# frozen_string_literal: true

module EE
  module Gitlab
    module ImportSources
      extend ::Gitlab::Utils::Override

      EE_PROJECT_TEMPLATE_IMPORTERS = ['gitlab_custom_project_template'].freeze

      override :import_table
      def import_table
        super + ee_import_table
      end

      def ee_import_table
        # This method can be called/loaded before the database
        # has been created. With this guard clause we prevent querying
        # the License table until the table exists
        return [] unless License.database.cached_table_exists? &&
          License.feature_available?(:custom_project_templates)

        [::Gitlab::ImportSources::ImportSource.new('gitlab_custom_project_template',
          'GitLab custom project template export',
          ::Gitlab::ImportExport::Importer)]
      end

      override :project_template_importers
      def project_template_importers
        (super + EE_PROJECT_TEMPLATE_IMPORTERS).freeze
      end

      override :pull_mirror?
      def pull_mirror?(project)
        project.mirror?
      end
    end
  end
end
