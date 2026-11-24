# frozen_string_literal: true

module Import
  module Sync
    module Repositories
      # Brings a repository's GitHub issues, pull requests, comments, reviews, issue events and releases up to date.
      # A single pass can span several Sidekiq jobs, so progress is checkpointed in a cursor after each page.
      # Replaying a page is safe because applying an object twice is a no-op.
      class ReconcileWorkItemsService < BaseReconcileService
        DOMAIN = 'work_items'
        SAFETY_OVERLAP = 5.minutes
        FAILURE_CODE = 'github_work_items_update_failed'
        FAILURE_MESSAGE = 'GitHub work item update failed'
        FAILURE_LOG_MESSAGE = 'GitHub work item reconciliation failed'
        PLACEHOLDER_LOAD_FAILURE_MESSAGE = 'GitHub placeholder references could not be saved'
        CURSOR_PHASES = %w[issues comments review_comments events releases].freeze
        MAX_PROVIDER_PAGES_PER_INVOCATION = 5
        FORK_BRANCH_PREFIX = 'github/fork/'

        private

        def reconcile_under_lease(lease_context)
          @pages_processed = 0
          @follow_up_required = false

          target = prepare_target
          return result([], false) unless target

          reconciler = WorkItems::ReconcileObjectService.new(
            repository,
            client: provider_client,
            verify_fence: -> { lease_context.verify! }
          )

          phases = CURSOR_PHASES.drop(CURSOR_PHASES.index(target[:phase]))
          phases.each_with_index do |phase, index|
            target = reconcile_cursor_phase(phase, reconciler, target, lease_context)
            next_phase = phases[index + 1]
            break if @follow_up_required || next_phase.nil?

            target = persist_cursor!(target.merge(phase: next_phase, page_url: nil), lease_context: lease_context)
            @follow_up_required = !pages_left?
            break if @follow_up_required
          end
          return result([], true) if @follow_up_required

          verify_application_fence!(lease_context)
          apply_success(target)
        end

        def reconcile_cursor_phase(phase, reconciler, cursor, lease_context)
          case phase
          when 'issues' then reconcile_issues(reconciler, cursor, lease_context)
          when 'comments' then reconcile_comments(reconciler, cursor, lease_context)
          when 'review_comments'
            cursor = reconcile_review_comments(reconciler, cursor, lease_context)
            return cursor if @follow_up_required

            WorkItems::RemoveDeletedReviewCommentsService.new(
              repository,
              client: provider_client,
              lease_context: lease_context
            ).execute

            cursor
          when 'events' then reconcile_events(cursor, lease_context)
          else reconcile_releases(cursor, lease_context)
          end
        end

        # A resumed pass keeps its original generation, start time and overlap window.
        # A newer desired generation that arrived meanwhile stays pending for a follow-up pass.
        def prepare_target
          repository.with_lock do
            next unless application_current?

            state = locked_state
            next unless state.lagging?

            cursor = resumable_cursor(state) || new_cursor(state)
            state.update!(state: :running, last_sync_started_at: cursor[:started_at], cursor: encode_cursor(cursor))
            cursor
          end
        end

        # Before the first pass, the import already copied everything older than the sync repository, so the
        # window starts at its creation rather than at the beginning of the repository's history.
        def new_cursor(state)
          since = (state.last_successful_sync_at || repository.created_at) - SAFETY_OVERLAP

          { generation: state.desired_generation, started_at: now.call, since: since, phase: 'issues', page_url: nil }
        end

        # A cursor from a finished generation, or one this code cannot read, is dropped so the
        # pass restarts from scratch instead of failing on every retry. Replaying is idempotent.
        def resumable_cursor(state)
          return if state.cursor.blank?

          cursor = decode_cursor(state.cursor)
          if cursor.nil?
            log_discarded_cursor
            return
          end

          cursor if cursor[:generation].between?(state.synced_generation + 1, state.desired_generation)
        end

        def log_discarded_cursor
          ::Gitlab::GithubImport::Logger.warn(
            message: 'discarding invalid GitHub work item cursor',
            import_sync_repository_id: repository.id,
            Labkit::Fields::GL_PROJECT_ID => project.id,
            domain: DOMAIN
          )
        end

        def reconcile_issues(reconciler, cursor, lease_context)
          comment_remover = WorkItems::RemoveDeletedCommentsService.new(
            repository,
            client: provider_client,
            lease_context: lease_context
          )

          reconcile_phase(cursor, lease_context, 'issues', :issues, issue_options(cursor[:since])) do |provider_issue|
            unchanged = reconciler.listed_version_applied?(provider_issue)
            noteable =
              if provider_issue[:pull_request]
                reconcile_pull_request(reconciler, provider_issue, lease_context, unchanged: unchanged)
              else
                representation = ::Gitlab::GithubImport::Representation::Issue.from_api_response(
                  provider_issue,
                  work_item_type_id: work_item_type_id
                )
                reconciler.execute(kind: :issue, provider_object: provider_issue, representation: representation)
              end

            comment_remover.execute(noteable, provider_issue, unchanged: unchanged) if noteable
          end
        end

        def reconcile_comments(reconciler, cursor, lease_context)
          options = comment_options(cursor[:since])

          reconcile_phase(cursor, lease_context, 'comments', :issues_comments, options) do |provider_comment|
            representation = ::Gitlab::GithubImport::Representation::Note.from_api_response(provider_comment)
            reconciler.execute(kind: :issue_comment, provider_object: provider_comment, representation: representation)
          end
        end

        def reconcile_review_comments(reconciler, cursor, lease_context)
          options = comment_options(cursor[:since]).merge(sort: 'created', direction: 'asc')

          reconcile_phase(cursor, lease_context, 'review_comments', :pull_requests_comments, options) do |comment|
            representation = review_comment_representation(reconciler, comment)
            reconciler.execute(kind: :review_comment, provider_object: comment, representation: representation)
          end
        end

        # The phase ends at the first page that reaches back past the pass's window.
        # GitHub answers 422 past page 300, the oldest events it serves; a 422 from applying an event still fails.
        def reconcile_events(cursor, lease_context)
          events = WorkItems::ReconcileIssueEventService.new(repository, client: provider_client)
          # Relies on the endpoint's newest-first order, verified against the live API.
          window_reached = ->(event) { cursor[:since].present? && event[:created_at].to_time < cursor[:since] }
          applying = false

          reconcile_phase(cursor, lease_context, 'events', :repository_issue_events, {},
            stop_when: window_reached) do |event|
            applying = true
            events.execute(event)
            applying = false
          end
        rescue ::Octokit::UnprocessableEntity => error
          raise if applying

          ::Gitlab::ErrorTracking.track_exception(
            error, import_sync_repository_id: repository.id, project_id: project.id
          )
          ::Gitlab::GithubImport::Logger.warn(
            message: 'GitHub issue events beyond the reachable history were not read',
            import_sync_repository_id: repository.id,
            Labkit::Fields::GL_PROJECT_ID => project.id,
            domain: DOMAIN
          )

          cursor
        end

        def reconcile_releases(cursor, lease_context)
          if cursor[:page_url].nil?
            WorkItems::RemoveDeletedReleasesService.new(
              repository,
              client: provider_client,
              lease_context: lease_context
            ).execute
          end

          release_reconciler = WorkItems::ReconcileReleaseService.new(
            repository,
            client: provider_client,
            verify_fence: -> { lease_context.verify! }
          )

          reconcile_phase(cursor, lease_context, 'releases', :releases, {}) do |provider_release|
            release_reconciler.execute(provider_release)
          end
        end

        def review_comment_representation(reconciler, comment)
          representation = ::Gitlab::GithubImport::Representation::DiffNote.from_api_response(comment)
          return representation unless comment[:in_reply_to_id]

          discussion_id = reconciler.review_comment_discussion_id(comment[:in_reply_to_id])
          return representation unless discussion_id

          ::Gitlab::GithubImport::Representation::DiffNote.from_json_hash(
            representation.to_hash.merge(discussion_id: discussion_id)
          )
        end

        # A stop_when match ends the phase after its page, whatever pages follow.
        def reconcile_phase(cursor, lease_context, phase, collection, options, stop_when: nil)
          provider_client.each_page(collection, cursor[:page_url], repository.provider_full_name, options) do |page|
            last_page = false

            # Attachment rewrites and diff rebuilds can make one page outlast the lease, so it is renewed per object.
            page.objects.each do |provider_object|
              lease_context.renew!
              provider_object = provider_object.to_h
              last_page ||= stop_when.present? && stop_when.call(provider_object)
              yield provider_object
            end

            load_placeholder_references!
            cursor = checkpoint_page!(cursor, page, phase: phase, lease_context: lease_context, last_page: last_page)
            break if last_page || @follow_up_required
          end

          cursor
        end

        def reconcile_pull_request(reconciler, provider_issue, lease_context, unchanged:)
          return project.merge_requests.find_by_iid(provider_issue[:number]) if unchanged

          provider_pull_request = provider_client.pull_request(repository.provider_full_name, provider_issue[:number])
          lease_context.renew!
          representation = ::Gitlab::GithubImport::Representation::PullRequest.from_api_response(provider_pull_request)
          version_applied = reconciler.provider_version_applied?(
            kind: :pull_request, provider_object: provider_pull_request, representation: representation
          )

          if !version_applied && head_fetch_required?(representation)
            fetch_pull_request_head(representation, lease_context)
          end

          reconciler.execute(
            kind: :pull_request,
            provider_object: provider_pull_request,
            representation: representation
          ) { reconcile_reviews(reconciler, representation.iid, lease_context) }
        end

        def reconcile_reviews(reconciler, pull_request_iid, lease_context)
          reviews = provider_client.pull_request_reviews(repository.provider_full_name, pull_request_iid)

          reviews.each do |provider_review|
            lease_context.renew!
            next if provider_review[:state] == 'PENDING'

            representation = ::Gitlab::GithubImport::Representation::PullRequestReview.from_api_response(
              provider_review.merge(merge_request_iid: pull_request_iid, body: provider_review[:body].to_s)
            )
            reconciler.execute_review(provider_object: provider_review, representation: representation)
          end
        end

        # Fork commits are never reachable from the mirrored heads, and a same-repo head is gone too once its
        # branch was deleted on GitHub. Rebuilding the diff without the commit would replace it with an empty one.
        def head_fetch_required?(pull_request)
          pull_request.cross_project? || project.repository.commit(pull_request.source_branch_sha).nil?
        end

        # The fork branch is written by this fetch rather than by the importer's add_branch, which runs the Git
        # hooks and would start pipelines from the fork's CI config. Closed pull requests get no branch, as in
        # the initial import.
        def fetch_pull_request_head(pull_request, lease_context)
          iid = Integer(pull_request.iid, exception: false)
          raise ArgumentError, 'GitHub pull request identity is invalid' unless iid&.positive?

          refmap = ["+refs/pull/#{iid}/head:refs/merge-requests/#{iid}/head"]
          fork_branch = fork_branch_to_write(pull_request)
          refmap << "+refs/pull/#{iid}/head:refs/heads/#{fork_branch}" if fork_branch

          verify_application_fence!(lease_context)

          fetch_result = project.repository.fetch_as_mirror(
            authentication.repository_url,
            refmap: refmap,
            forced: true,
            no_tags: true,
            prune: false,
            http_authorization_header: authentication.http_authorization_header,
            resolved_address: authentication.resolved_address
          )
          request_lfs_pass if fetch_result.repo_changed && !allow_cutover
          # The importer consults the cached branch list before creating the branch itself.
          project.repository.expire_branches_cache if fork_branch
          lease_context.renew!
        end

        # The importer drops the github/fork/ prefix when the fork owner's account is gone. A forced write
        # outside that namespace could overwrite a base repository branch of the same name, so only
        # namespaced branches are written here; the importer's existence check still covers the rest.
        def fork_branch_to_write(pull_request)
          return unless pull_request.cross_project? && pull_request.state == :opened

          branch = pull_request.formatted_source_branch
          branch if branch.to_s.start_with?(FORK_BRANCH_PREFIX)
        end

        # Newest first: an edit mid-pass pushes items later, so one is read twice, which is harmless.
        # Oldest first would skip one, and the next pass's overlap window would miss it.
        def issue_options(since_time)
          options = { state: 'all', sort: 'updated', direction: 'desc' }
          options[:since] = since_time.iso8601 if since_time
          options
        end

        def comment_options(since_time)
          options = { sort: 'updated', direction: 'desc' }
          options[:since] = since_time.iso8601 if since_time
          options
        end

        # On the last page the saved cursor keeps that page's own URL rather than nil.
        # A crash before the phase finishes then replays only that page instead of restarting the whole phase.
        def checkpoint_page!(cursor, page, phase:, lease_context:, last_page: false)
          next_url = page.next_url unless last_page
          cursor = persist_cursor!(
            cursor.merge(phase: phase, page_url: next_url || page.url), lease_context: lease_context
          )
          @pages_processed += 1
          @follow_up_required = next_url.present? && !pages_left?

          cursor
        end

        def pages_left?
          @pages_processed < MAX_PROVIDER_PAGES_PER_INVOCATION
        end

        def persist_cursor!(cursor, lease_context:)
          lease_context.verify!

          repository.with_lock do
            unless application_current?
              raise Errors::StaleApplicationError, 'GitHub updates changed while work item progress was being saved'
            end

            state = locked_state
            unless state.lagging? && decode_cursor(state.cursor)&.dig(:generation) == cursor[:generation]
              raise Errors::StaleApplicationError, 'GitHub work item progress changed during reconciliation'
            end

            state.update!(cursor: encode_cursor(cursor))
          end

          cursor
        end

        def decode_cursor(raw_cursor)
          payload = ::Gitlab::Json::SafeParser.parse(raw_cursor.to_s)
          generation, phase, page_url = payload.values_at('generation', 'phase', 'page_url')
          valid = generation.is_a?(Integer) && CURSOR_PHASES.include?(phase) &&
            (page_url.nil? || page_url.is_a?(String))
          raise ArgumentError, 'invalid cursor' unless valid

          {
            generation: generation,
            started_at: Time.iso8601(payload['started_at']).in_time_zone,
            since: payload['since'] && Time.iso8601(payload['since']).in_time_zone,
            phase: phase,
            page_url: page_url
          }
        rescue JSON::ParserError, ArgumentError, TypeError, NoMethodError
          nil
        end

        def encode_cursor(cursor)
          ::Gitlab::Json.generate(
            generation: cursor[:generation],
            started_at: cursor[:started_at].iso8601(6),
            since: cursor[:since]&.iso8601(6),
            phase: cursor[:phase],
            page_url: cursor[:page_url]
          )
        end

        # last_successful_sync_at is set to when the pass started, not when it finished, so an item that changed
        # after its page was read during a long pass still falls inside the next pass's overlap window.
        def apply_success(target)
          follow_up = false

          repository.with_lock do
            unless application_current?
              raise Errors::StaleApplicationError, 'GitHub updates changed while work items were being applied'
            end

            state = locked_state
            persisted_cursor = decode_cursor(state.cursor)
            unless persisted_cursor && persisted_cursor[:phase] == 'releases' &&
                persisted_cursor[:generation] == target[:generation]
              raise Errors::StaleApplicationError, 'GitHub work item progress changed before checkpointing'
            end

            state.synced_generation = [state.synced_generation, target[:generation]].max
            state.state = state.lagging? ? :pending : :current
            state.last_successful_sync_at = target[:started_at]
            state.cursor = nil
            state.last_error_code = nil
            state.last_error_message = nil
            state.save!
            follow_up = state.lagging?
          end

          result([DOMAIN], follow_up)
        end

        def record_failure!(error)
          repository.with_lock do
            state = locked_state
            mark_failed!(state, error) if state.running? || (state.cursor.present? && state.lagging?)
          end
        end

        def locked_state
          repository.sync_states_for_update([DOMAIN]).fetch(DOMAIN)
        end

        # Runs before the page checkpoint, so a failure leaves the cursor on this page and the retry replays it.
        def load_placeholder_references!
          import_state = project.import_state
          return unless import_state&.id
          return unless project.placeholder_reference_store.any?

          response = ::Import::PlaceholderReferences::LoadService.new(
            import_source: ::Import::SOURCE_GITHUB,
            import_uid: import_state.id
          ).execute
          return if response.payload[:error_count] == 0

          raise Errors::PlaceholderReferenceLoadError, PLACEHOLDER_LOAD_FAILURE_MESSAGE
        rescue Errors::PlaceholderReferenceLoadError
          raise
        rescue StandardError => error
          ::Gitlab::ErrorTracking.track_exception(
            error, import_sync_repository_id: repository.id, project_id: project.id
          )
          raise Errors::PlaceholderReferenceLoadError, PLACEHOLDER_LOAD_FAILURE_MESSAGE, cause: nil
        end

        def work_item_type_id
          @work_item_type_id ||= ::WorkItems::TypesFramework::Provider.new(project).default_issue_type.id
        end
      end
    end
  end
end
