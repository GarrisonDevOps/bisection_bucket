# frozen_string_literal: true

module Import
  module Sync
    module Repositories
      module WorkItems
        # Creates the label and milestone events made on GitHub after the import, as the initial import does.
        # An event is skipped when its issue, merge request, label or milestone is not in GitLab, or when an event
        # with the same issuable, label or milestone, action and time exists, so replays and imported events are no-ops.
        class ReconcileIssueEventService
          IMPORTERS = {
            'labeled' => ::Gitlab::GithubImport::Importer::Events::ChangedLabel,
            'unlabeled' => ::Gitlab::GithubImport::Importer::Events::ChangedLabel,
            'milestoned' => ::Gitlab::GithubImport::Importer::Events::ChangedMilestone,
            'demilestoned' => ::Gitlab::GithubImport::Importer::Events::ChangedMilestone
          }.freeze

          def initialize(repository, client:)
            @project = repository.project
            @client = client
          end

          def execute(provider_event)
            importer_class = IMPORTERS[provider_event[:event]]
            return unless importer_class && provider_event[:issue]

            event = ::Gitlab::GithubImport::Representation::IssueEvent.from_api_response(provider_event)
            issuable = find_issuable(event)
            return unless issuable

            if importer_class == ::Gitlab::GithubImport::Importer::Events::ChangedLabel
              label_id = project.labels.with_title(event.label_title).pick(:id)
              return unless label_id && !label_event_exists?(event, issuable, label_id)

              # The finder caches misses for 24 hours, and its miss would write an event with no label.
              label_finder = ::Gitlab::GithubImport::LabelFinder.new(project)
              ::Gitlab::Cache::Import::Caching.write(label_finder.cache_key_for(event.label_title), label_id)
            else
              milestone_id = project.milestones.find_by_title(event.milestone_title)&.id
              return unless milestone_id && !milestone_event_exists?(event, issuable, milestone_id)
            end

            # The finder caches misses for 72 hours, and its miss would write an event with no issue.
            ::Gitlab::GithubImport::IssuableFinder.new(project, event).cache_database_id(issuable.id)
            importer_class.new(project, client).execute(event)
          end

          private

          attr_reader :project, :client

          def find_issuable(event)
            issuables = event.issuable_type == ::MergeRequest.name ? project.merge_requests : project.issues
            issuables.find_by_iid(event.issuable_id)
          end

          def label_event_exists?(event, issuable, label_id)
            action = event.event == 'unlabeled' ? :remove : :add
            ::ResourceLabelEvent.exists?( # rubocop:disable CodeReuse/ActiveRecord -- one indexed natural-key lookup
              issuable_key(issuable) => issuable.id, label_id: label_id, action: action, created_at: event.created_at
            )
          end

          def milestone_event_exists?(event, issuable, milestone_id)
            action = event.event == 'demilestoned' ? :remove : :add
            ::ResourceMilestoneEvent.exists?( # rubocop:disable CodeReuse/ActiveRecord -- one indexed natural-key lookup
              issuable_key(issuable) => issuable.id,
              milestone_id: milestone_id,
              action: action,
              created_at: event.created_at
            )
          end

          def issuable_key(issuable)
            issuable.is_a?(::MergeRequest) ? :merge_request_id : :issue_id
          end
        end
      end
    end
  end
end
