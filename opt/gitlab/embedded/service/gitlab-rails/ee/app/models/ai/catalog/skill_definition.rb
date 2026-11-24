# frozen_string_literal: true

module Ai
  module Catalog
    class SkillDefinition < BaseDefinition
      def path
        version.def_path
      end

      def git_ref
        version.def_git_ref
      end

      # Content-addressed, so publishing an unchanged SKILL.md produces an identical definition.
      def blob_sha
        version.def_blob_sha
      end

      # Provenance only; change detection uses blob_sha.
      def commit_sha
        version.def_commit_sha
      end

      # Git attribution need not correspond to a GitLab user, so the name is kept even when
      # the version's created_by is nil.
      def author_name
        version.def_author_name
      end

      # The skill is the directory, not the file, so consumers can resolve co-located resources.
      def directory
        File.dirname(path)
      end
    end
  end
end
