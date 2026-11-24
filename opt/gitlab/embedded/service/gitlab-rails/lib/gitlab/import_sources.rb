# frozen_string_literal: true

# Gitlab::ImportSources module
#
# Define import sources that can be used
# during the creation of new project
module Gitlab
  module ImportSources
    ImportSource = Struct.new(:name, :title, :importer)

    IMPORT_TABLE = [
      ImportSource.new('github',           'GitHub',            Gitlab::GithubImport::ParallelImporter),
      ImportSource.new('bitbucket',        'Bitbucket Cloud',   Gitlab::BitbucketImport::ParallelImporter),
      ImportSource.new('bitbucket_server', 'Bitbucket Server',  Gitlab::BitbucketServerImport::ParallelImporter),
      ImportSource.new('fogbugz',          'FogBugz',           Gitlab::FogbugzImport::Importer),
      ImportSource.new('git',              'Repository by URL', nil),
      ImportSource.new('gitlab_project',   'GitLab export',     Gitlab::ImportExport::Importer),
      ImportSource.new('gitea',            'Gitea',             Gitlab::LegacyGithubImport::Importer),
      ImportSource.new('manifest',         'Manifest file',     nil),
      ImportSource.new(
        'gitlab_built_in_project_template', 'GitLab built-in project template', Gitlab::ImportExport::Importer
      )
    ].freeze

    PROJECT_TEMPLATE_IMPORTERS = ['gitlab_built_in_project_template'].freeze

    class << self
      prepend_mod_with('Gitlab::ImportSources') # rubocop: disable Cop/InjectEnterpriseEditionModule

      def values
        import_table.map(&:name)
      end

      def import_source(name)
        import_table.find { |import_source| import_source.name == name }
      end

      def has_importer?(name)
        importer(name).present?
      end

      def template?(name)
        project_template_importers.include?(name)
      end

      def importer(name)
        import_source(name)&.importer
      end

      def title(name)
        import_source(name)&.title
      end

      def import_table
        IMPORT_TABLE
      end

      def project_template_importers
        PROJECT_TEMPLATE_IMPORTERS
      end

      def importable_project_types
        values - project_template_importers
      end

      # Only sources the `import_sources` setting controls are checked, everything else passes
      def enabled?(name)
        name = name.to_s
        return true unless importable_project_types.include?(name)

        Gitlab::CurrentSettings.import_sources.to_a.include?(name)
      end

      # Pull mirrors are EE only, the raw `projects.mirror` column means nothing in CE
      def pull_mirror?(_project)
        false
      end

      # A stored `import_url` gets cloned whatever the type, so an ungoverned type counts as `git`.
      def effective_import_type(project)
        return 'git' if project.external_import? && project.import_type.present? &&
          importable_project_types.exclude?(project.import_type)

        project.import_type
      end
    end
  end
end
