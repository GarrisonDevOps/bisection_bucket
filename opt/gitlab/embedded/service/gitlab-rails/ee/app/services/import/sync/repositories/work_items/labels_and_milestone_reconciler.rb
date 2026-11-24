# frozen_string_literal: true

module Import
  module Sync
    module Repositories
      module WorkItems
        # Creates the labels and milestones added on GitHub after the import, and keeps an issue's or merge
        # request's labels in sync. A label or milestone GitLab cannot save is skipped for the rest of the run.
        class LabelsAndMilestoneReconciler
          def initialize(repository, client:)
            @repository = repository
            @project = repository.project
            @client = client
            @failed_label_names = Set.new
            @failed_milestone_iids = Set.new
          end

          def create_missing(provider_object, representation)
            create_missing_milestone(provider_object[:milestone], representation)
            create_missing_labels(Array(provider_object[:labels])) if provider_object.key?(:labels)
          end

          # Only label links are written. ReconcileIssueEventService creates the ResourceLabelEvents.
          def apply_labels(record, provider_object)
            return unless provider_object.key?(:labels)

            record.labels = project.labels.with_title(label_names(Array(provider_object[:labels])))
          end

          private

          attr_reader :repository, :project, :client, :failed_label_names, :failed_milestone_iids

          def create_missing_milestone(milestone, representation)
            return if milestone.nil? || failed_milestone_iids.include?(milestone[:number])
            return if milestone_finder.id_for(representation)

            if milestones_importer.already_imported?(milestone) ||
                save_provider_record(::Milestone.new(milestones_importer.build_attributes(milestone)))
              milestone_finder.build_cache
            else
              failed_milestone_iids << milestone[:number]
            end
          end

          def create_missing_labels(labels)
            existing_names = project.labels.with_title(label_names(labels)).map(&:title)
            missing_labels = labels.reject do |label|
              existing_names.include?(label[:name]) || failed_label_names.include?(label[:name])
            end

            missing_labels.each do |label|
              next if save_provider_record(::Label.new(labels_importer.build_attributes(label)))

              failed_label_names << label[:name]
            end
          end

          def label_names(labels)
            labels.filter_map { |label| label[:name] }
          end

          def save_provider_record(record)
            return true if record.save

            ::Gitlab::GithubImport::Logger.warn(
              message: 'skipping invalid GitHub label or milestone',
              import_sync_repository_id: repository.id,
              Labkit::Fields::GL_PROJECT_ID => project.id,
              object_type: record.class.base_class.name,
              errors: record.errors.full_messages
            )

            false
          end

          def labels_importer
            @labels_importer ||= ::Gitlab::GithubImport::Importer::LabelsImporter.new(project, client)
          end

          def milestones_importer
            @milestones_importer ||= ::Gitlab::GithubImport::Importer::MilestonesImporter.new(project, client)
          end

          def milestone_finder
            @milestone_finder ||= ::Gitlab::GithubImport::MilestoneFinder.new(project)
          end
        end
      end
    end
  end
end
