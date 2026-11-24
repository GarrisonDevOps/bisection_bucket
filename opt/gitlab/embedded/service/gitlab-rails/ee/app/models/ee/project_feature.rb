# frozen_string_literal: true

module EE
  module ProjectFeature
    extend ActiveSupport::Concern

    # When updating this array, make sure to update rubocop/cop/gitlab/feature_available_usage.rb as well.
    EE_FEATURES = %i[requirements].freeze
    NOTES_PERMISSION_TRACKED_FIELDS = %w[
      issues_access_level
      repository_access_level
      merge_requests_access_level
      snippets_access_level
    ].freeze

    MILESTONE_PERMISSION_TRACKED_FIELDS = %w[
      issues_access_level
      merge_requests_access_level
    ].freeze

    prepended do
      set_available_features(EE_FEATURES)

      # Ensure changes to project visibility settings go to Elasticsearch if the tracked field(s) change
      after_commit :update_project_in_index, on: :update, if: -> { project.maintaining_elasticsearch? }
      after_commit :update_project_associations_in_index, on: :update, if: -> {
        project.maintaining_elasticsearch? && project.maintaining_indexed_associations?
      }
      after_commit :update_unindexed_project_snippets_in_index, on: :update, if: -> {
        project.maintaining_elasticsearch? && !project.maintaining_indexed_associations? &&
          elasticsearch_project_snippets_need_updating?
      }

      attribute :requirements_access_level, default: Featurable::ENABLED

      private

      def update_project_in_index
        project.maintain_elasticsearch_update
      end

      def update_project_associations_in_index
        associations_to_update = [].tap do |associations|
          associations << 'issues' if elasticsearch_project_issues_need_updating?
          associations << 'merge_requests' if elasticsearch_project_merge_requests_need_updating?
          associations << 'notes' if elasticsearch_project_notes_need_updating?
          associations << 'milestones' if elasticsearch_project_milestones_need_updating?
          associations << 'snippets' if elasticsearch_project_snippets_need_updating?
        end

        if associations_to_update.any?
          ElasticAssociationIndexerWorker.perform_async(project.class.name, project_id, associations_to_update)
        end

        if elasticsearch_project_blobs_need_updating? && !::Gitlab::Geo.secondary?
          ::Search::Elastic::CommitIndexerWorker.perform_async(project.id, { 'force' => true })
        end

        return unless elasticsearch_project_wikis_need_updating?

        ElasticWikiIndexerWorker.perform_async(project.id, project.class.name, { 'force' => true })
      end

      def elasticsearch_project_milestones_need_updating?
        previous_changes.keys.any? { |key| MILESTONE_PERMISSION_TRACKED_FIELDS.include?(key) }
      end

      def elasticsearch_project_notes_need_updating?
        previous_changes.keys.any? { |key| NOTES_PERMISSION_TRACKED_FIELDS.include?(key) }
      end

      def update_unindexed_project_snippets_in_index
        ElasticAssociationIndexerWorker.perform_async(project.class.name, project_id, %w[snippets])
      end

      def elasticsearch_project_snippets_need_updating?
        previous_changes.key?(:snippets_access_level) &&
          ::Elastic::DataMigrationService.migration_has_finished?(:add_project_visibility_level_to_snippets)
      end

      def elasticsearch_project_issues_need_updating?
        previous_changes.key?(:issues_access_level)
      end

      def elasticsearch_project_merge_requests_need_updating?
        previous_changes.key?(:merge_requests_access_level)
      end

      def elasticsearch_project_blobs_need_updating?
        previous_changes.key?(:repository_access_level)
      end

      def elasticsearch_project_wikis_need_updating?
        previous_changes.key?(:wiki_access_level)
      end
    end
  end
end
