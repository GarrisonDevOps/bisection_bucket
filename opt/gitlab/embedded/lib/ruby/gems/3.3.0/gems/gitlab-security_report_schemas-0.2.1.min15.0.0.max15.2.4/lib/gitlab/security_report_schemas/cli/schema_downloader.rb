# frozen_string_literal: true

require "git"
require "fileutils"

module Gitlab
  module SecurityReportSchemas
    module CLI
      # Copies the schema for the given version to the project
      class SchemaDownloader
        def self.download(version)
          new(version).download
        end

        def initialize(version)
          @version = version
        end

        def download
          checkout_version
          create_target_directory
          copy_schemas
        end

        private

        attr_reader :version

        def checkout_version
          git_project.checkout("v#{version}")
        end

        def create_target_directory
          FileUtils.mkdir_p(target_directory) unless File.exist?(target_directory)
        end

        def copy_schemas
          FileUtils.cp(dist_path.children, target_directory)
        end

        def target_directory
          @target_directory ||= SecurityReportSchemas.schemas_path.join(version)
        end

        def dist_path
          SecurityReportSchemas.root_path.join("tmp", "security-report-schemas", "dist")
        end

        def git_project
          @git_project ||= existing_repository || clone_repository
        end

        def existing_repository
          return unless File.exist?(git_project_path)

          Git.open(git_project_path)
        end

        def clone_repository
          Git.clone(Gitlab::SecurityReportSchemas.configuration.schema_repository, git_project_path)
        end

        def git_project_path
          @git_project_path ||= SecurityReportSchemas.root_path.join("tmp", "security-report-schemas")
        end
      end
    end
  end
end
