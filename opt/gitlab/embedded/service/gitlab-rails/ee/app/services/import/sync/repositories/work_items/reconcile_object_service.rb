# frozen_string_literal: true

module Import
  module Sync
    module Repositories
      module WorkItems
        # Applies one GitHub issue, pull request, comment or review to GitLab.
        # Records are found only through Import::Sync::ExternalObject mappings, never by IID.
        # A new record is claimed by an unversioned mapping as soon as it exists.
        # The version is written last, so a failure part-way through is redone on the next pass.
        class ReconcileObjectService
          KIND_CONFIGURATION = {
            issue: { local_type: 'Issue', importer: ::Gitlab::GithubImport::Importer::IssueImporter },
            pull_request: {
              local_type: 'MergeRequest',
              importer: ::Gitlab::GithubImport::Importer::PullRequestImporter
            },
            issue_comment: { local_type: 'Note', importer: ::Gitlab::GithubImport::Importer::NoteImporter },
            review_comment: { local_type: 'Note', importer: ::Gitlab::GithubImport::Importer::DiffNoteImporter }
          }.freeze
          NOTE_KINDS = %i[issue_comment review_comment].freeze

          def initialize(repository, client:, verify_fence:)
            @repository = repository
            @project = repository.project
            @client = client
            @verify_fence = verify_fence
          end

          def execute(kind:, provider_object:, representation:)
            configuration = KIND_CONFIGURATION.fetch(kind)
            provider_object_xid = positive_provider_object_xid(provider_object)
            provider_updated_at = provider_timestamp(representation.updated_at)
            importer = configuration[:importer].new(representation, project, client)
            mapping = Import::Sync::ExternalObject.for_provider(
              repository: repository,
              kind: kind,
              provider_object_xid: provider_object_xid
            )

            local_record = resolve_local_record(mapping, configuration[:local_type])

            if local_record.nil? && skip_unmapped?(kind, representation, importer)
              log_skipped_unmapped(kind, representation)
              return
            end

            validate_local_record!(local_record, configuration[:local_type], representation) if local_record

            # A mapping at or past this version means the record was fully applied, even if its body now
            # differs after attachment links were rewritten.
            return local_record if version_applied?(mapping, provider_updated_at)

            verify_fence.call
            # import_attributes is memoized, so the missing milestone has to exist before it is first called.
            labels_and_milestone.create_missing(provider_object, representation) if issuable?(kind)

            attributes = importer.import_attributes
            # The representation draws a random discussion id on every build; an update must keep the one
            # assigned at creation.
            attributes = attributes.except(:discussion_id) if NOTE_KINDS.include?(kind)
            # A milestone GitLab could not save resolves to nil, which would clear the current one.
            attributes = attributes.except(:milestone_id) if unresolved_milestone?(kind, representation, attributes)
            invalidate_counter_cache = counter_cache_invalidation_required?(kind, local_record, attributes)

            local_record =
              if local_record
                update_record(local_record, attributes, importer, kind, invalidate_counter_cache)
              else
                create_record(importer, kind, representation, provider_object_xid, invalidate_counter_cache)
              end

            validate_local_record!(local_record, configuration[:local_type], representation)
            yield if block_given?
            verify_fence.call
            labels_and_milestone.apply_labels(local_record, provider_object) if issuable?(kind)
            Import::Sync::ExternalObject.record!(
              repository: repository,
              kind: kind,
              provider_object_xid: provider_object_xid,
              local_record: local_record,
              provider_updated_at: provider_updated_at
            )

            local_record
          end

          # Lets the caller skip a fork head fetch; a mapping that is already newer counts as applied too.
          def provider_version_applied?(kind:, provider_object:, representation:)
            mapping = Import::Sync::ExternalObject.for_provider(
              repository: repository,
              kind: kind,
              provider_object_xid: positive_provider_object_xid(provider_object)
            )

            version_applied?(mapping, provider_timestamp(representation.updated_at))
          end

          def listed_pull_request_applied?(provider_issue)
            merge_request = project.merge_requests.find_by_iid(provider_issue[:number])
            return false unless merge_request

            mapping = Import::Sync::ExternalObject.for_local_record(repository: repository, local_record: merge_request)
            version_applied?(mapping, provider_timestamp(provider_issue[:updated_at]))
          end

          def review_comment_discussion_id(provider_comment_xid)
            Import::Sync::ExternalObject.for_provider(
              repository: repository,
              kind: :review_comment,
              provider_object_xid: provider_comment_xid
            )&.note&.discussion_id
          end

          def execute_review(provider_object:, representation:)
            provider_object_xid = positive_provider_object_xid(provider_object)
            submitted_at = provider_timestamp(representation.submitted_at)
            mapping = Import::Sync::ExternalObject.for_provider(
              repository: repository,
              kind: :review,
              provider_object_xid: provider_object_xid
            )
            return if version_applied?(mapping, submitted_at)

            verify_fence.call
            create_review(
              ::Gitlab::GithubImport::Importer::PullRequests::ReviewImporter.new(representation, project, client),
              provider_object_xid,
              submitted_at,
              mapping
            )
          end

          def listed_version_applied?(provider_issue)
            return listed_pull_request_applied?(provider_issue) if provider_issue[:pull_request]

            mapping = Import::Sync::ExternalObject.for_provider(
              repository: repository,
              kind: :issue,
              provider_object_xid: positive_provider_object_xid(provider_issue)
            )

            version_applied?(mapping, provider_timestamp(provider_issue[:updated_at]))
          end

          private

          attr_reader :repository, :project, :client, :verify_fence

          def positive_provider_object_xid(provider_object)
            provider_object_xid = provider_object[:id].to_i
            return provider_object_xid if provider_object_xid > 0

            raise Errors::ProviderObjectError, 'GitHub object identity is invalid'
          end

          def provider_timestamp(value)
            timestamp = value&.in_time_zone
            return timestamp if timestamp

            raise Errors::ProviderObjectError, 'GitHub object update time is invalid'
          rescue NoMethodError, ArgumentError
            raise Errors::ProviderObjectError, 'GitHub object update time is invalid'
          end

          def version_applied?(mapping, provider_updated_at)
            mapping&.provider_updated_at.present? && mapping.provider_updated_at >= provider_updated_at
          end

          def unresolved_milestone?(kind, representation, attributes)
            issuable?(kind) && representation.milestone_number.present? && attributes[:milestone_id].nil?
          end

          def issuable?(kind)
            NOTE_KINDS.exclude?(kind)
          end

          def labels_and_milestone
            @labels_and_milestone ||= LabelsAndMilestoneReconciler.new(repository, client: client)
          end

          def resolve_local_record(mapping, expected_type)
            return unless mapping

            local_record = mapping.local_record
            unless local_record && local_record.class.base_class.name == expected_type
              raise Errors::MappingConflictError, 'GitHub object mapping has the wrong GitLab record type'
            end

            local_record
          end

          # Without a mapping only provably new objects are created: an existing
          # same-IID issue or merge request, or a comment whose parent is missing or
          # unmapped, is skipped rather than adopted.
          def skip_unmapped?(kind, representation, importer)
            return !mapped_parent?(representation, importer) if NOTE_KINDS.include?(kind)

            issuables(kind).exists?(iid: representation.iid) # rubocop:disable CodeReuse/ActiveRecord -- existence check only
          end

          def issuables(kind)
            kind == :issue ? project.issues : project.merge_requests
          end

          def mapped_parent?(representation, importer)
            noteable_id = importer.find_noteable_id
            return false unless noteable_id

            noteable_class = representation.noteable_type == 'MergeRequest' ? MergeRequest : Issue
            parent = noteable_class.find_by(id: noteable_id, project_id: project.id) # rubocop:disable CodeReuse/ActiveRecord -- single project-scoped lookup
            return false unless parent

            Import::Sync::ExternalObject.for_local_record(repository: repository, local_record: parent).present?
          end

          def log_skipped_unmapped(kind, representation)
            iid = NOTE_KINDS.include?(kind) ? representation.noteable_id : representation.iid

            ::Gitlab::GithubImport::Logger.warn(
              message: 'skipping unmapped GitHub object',
              import_sync_repository_id: repository.id,
              Labkit::Fields::GL_PROJECT_ID => project.id,
              kind: kind,
              iid: iid
            )
          end

          def validate_local_record!(record, expected_type, representation)
            unless record && record.class.base_class.name == expected_type && record.project_id == project.id
              raise Errors::MappingConflictError, 'GitHub object mapping does not belong to the synced project'
            end

            unless record.imported_from_github?
              raise Errors::MappingConflictError, 'GitHub object mapping would overwrite a GitLab-created record'
            end

            return if expected_type == 'Note' || record.iid == representation.iid

            raise Errors::MappingConflictError, 'GitHub object mapping has the wrong GitLab IID'
          end

          def update_record(record, attributes, importer, kind, invalidate_counter_cache)
            assignee_ids_before = record.try(:assignee_ids)
            git_data_changed = kind == :pull_request && git_data_changed?(record, importer.pull_request)
            # The importing flag keeps notifications and integrations quiet for these reconciliation writes.
            record.importing = true
            record.assign_attributes(attributes)
            importer.set_merge_request_assignees(record) if kind == :pull_request
            # touch: false keeps updated_at at the GitHub timestamp assigned from the importer attributes.
            record.save!(touch: false)
            record.invalidate_project_counter_caches if invalidate_counter_cache
            import_attachments(record)
            append_diff_version(record, importer) if git_data_changed
            # GitHub authors never change, so only new assignees can need a placeholder reference.
            importer.push_placeholder_references(record) if assignees_added?(record, assignee_ids_before)
            record
          end

          # Mirrors MergeRequests::ReloadDiffsService, which a native push goes through: past either limit
          # nothing is added and the latest diff stays as it is.
          def append_diff_version(merge_request, importer)
            if merge_request.reached_versions_limit? || merge_request.reached_diff_commits_limit?
              log_diff_limit_reached(merge_request)
              return
            end

            # Passing false adds a diff version; true would delete every existing one first.
            importer.insert_git_data(merge_request, false)
          end

          def log_diff_limit_reached(merge_request)
            ::Gitlab::GithubImport::Logger.info(
              message: 'skipping new merge request diff version, diff limit reached',
              import_sync_repository_id: repository.id,
              Labkit::Fields::GL_PROJECT_ID => project.id,
              merge_request_id: merge_request.id
            )
          end

          def assignees_added?(record, assignee_ids_before)
            return false if assignee_ids_before.nil?

            (record.assignee_ids - assignee_ids_before).any?
          end

          # Any comment or label edit bumps a pull request's updated_at, and a rebuild adds a diff version.
          def git_data_changed?(merge_request, pull_request)
            diff = merge_request.merge_request_diff

            diff.nil? || diff.head_commit_sha != pull_request.source_branch_sha ||
              merge_request.target_branch != pull_request.target_branch
          end

          def create_record(importer, kind, representation, provider_object_xid, invalidate_counter_cache)
            created_record = begin
              importer.execute
            rescue StandardError
              recover_created_record(importer, kind, representation, provider_object_xid, invalidate_counter_cache)
              raise
            end

            created_record = ::Note.find(importer.imported_note_id) if NOTE_KINDS.include?(kind)
            raise Errors::ProviderObjectError, 'GitHub object could not be created' unless created_record

            # The importer has already committed. Without this claim, a retry would skip the issue or
            # merge request, or insert the comment a second time.
            claim_record!(kind, provider_object_xid, created_record)
            created_record.invalidate_project_counter_caches if invalidate_counter_cache
            import_attachments(created_record)
            created_record
          end

          def create_review(importer, provider_object_xid, submitted_at, mapping)
            begin
              importer.execute(add_reviewer: false, add_review_note: mapping.nil?)
            rescue StandardError
              claim_review_note(importer, provider_object_xid) unless mapping
              raise
            end

            review_note = mapping&.local_record || importer.imported_note
            return unless review_note

            claim_record!(:review, provider_object_xid, review_note) unless mapping
            import_attachments(review_note)
            Import::Sync::ExternalObject.record!(
              repository: repository,
              kind: :review,
              provider_object_xid: provider_object_xid,
              local_record: review_note,
              provider_updated_at: submitted_at
            )
          end

          def claim_review_note(importer, provider_object_xid)
            return unless importer.imported_note

            claim_record!(:review, provider_object_xid, importer.imported_note)
          rescue StandardError => error
            ::Gitlab::ErrorTracking.track_exception(
              error, project_id: project.id, provider_kind: :review, provider_object_xid: provider_object_xid
            )
          end

          def claim_record!(kind, provider_object_xid, record)
            Import::Sync::ExternalObject.record!(
              repository: repository,
              kind: kind,
              provider_object_xid: provider_object_xid,
              local_record: record,
              provider_updated_at: nil
            )
          end

          # The attachments stage rewrites bodies with GitLab upload links after the initial import.
          # A reconciled body comes straight from GitHub again, so the rewrite has to be repeated.
          def import_attachments(record)
            return unless import_settings.enabled?(:attachments_import)

            # rubocop:disable Cop/AvoidBecomes -- NoteText accepts the Note base class only, not diff notes
            note_text = ::Gitlab::GithubImport::Representation::NoteText.from_db_record(
              record.is_a?(::Note) ? record.becomes(::Note) : record
            )
            # rubocop:enable Cop/AvoidBecomes
            ::Gitlab::GithubImport::Importer::NoteAttachmentsImporter.new(note_text, project, client).execute
          end

          def import_settings
            @import_settings ||= ::Gitlab::GithubImport::Settings.new(project)
          end

          def counter_cache_invalidation_required?(kind, record, attributes)
            return false unless issuable?(kind)

            record_class = kind == :issue ? Issue : MergeRequest
            target_state_id = record_class.type_for_attribute('state_id').cast(attributes.fetch(:state_id))
            target_open = target_state_id == record_class.available_states.fetch(:opened)

            record ? record.open? != target_open : target_open
          end

          # The importer may commit the record and then raise, for example if the pull request's
          # Git data write fails. Claim the record so the retry updates it, and invalidate its
          # counter cache, since the importer never reached that step.
          def recover_created_record(importer, kind, representation, provider_object_xid, invalidate_counter_cache)
            record = partially_created_record(importer, kind, representation)
            return unless record&.imported_from_github?

            claim_record!(kind, provider_object_xid, record)
            record.invalidate_project_counter_caches if invalidate_counter_cache
          rescue StandardError => error
            # The original importer error must be what propagates; recovery failures are only tracked.
            ::Gitlab::ErrorTracking.track_exception(
              error, project_id: project.id, provider_kind: kind, provider_object_xid: provider_object_xid
            )
          end

          # A same-IID record not imported from GitHub is someone else's, so it is not claimed.
          def partially_created_record(importer, kind, representation)
            return issuables(kind).find_by_iid(representation.iid) unless NOTE_KINDS.include?(kind)

            ::Note.find_by_id(importer.imported_note_id) if importer.imported_note_id
          end
        end
      end
    end
  end
end
