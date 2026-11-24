# frozen_string_literal: true

module Ai
  module FlowTriggers
    module FixLoop
      # Stops the fix loop of a merge request and tells the author why. A stopped loop marks the merge request
      # as a draft, because a push to a draft starts no review. The draft comes first, so a failed note still
      # stops the loop. An invalid configuration gets only the note: no loop runs to stop. An approval of the
      # reviewer ends the loop with only the note that the merge request is ready.
      class StopService
        include ::Gitlab::Loggable
        include ::Gitlab::Utils::StrongMemoize

        NOTES = {
          max_fix_runs: :max_fix_runs_note,
          fix_run_not_started: :fix_run_not_started_note,
          fix_run_without_push: :fix_run_without_push_note,
          invalid_config: :invalid_config_note,
          approved: :approved_note
        }.freeze
        DRAFT_REASONS = %i[max_fix_runs fix_run_not_started fix_run_without_push].freeze
        # The configuration stays invalid until someone changes it, and an approval event can come more than once.
        # So each later event would repeat these notes.
        NO_REPEAT_REASONS = %i[invalid_config approved].freeze

        # `details` has the values of the note: `reviewer` and `max_fix_runs` for :max_fix_runs, `fix_run` for
        # :fix_run_without_push, `errors` for :invalid_config, and `reviewer` and `fix_runs` for :approved.
        def initialize(merge_request, service_account:, reason:, details: {})
          raise ArgumentError, "Unknown reason: #{reason.inspect}" unless NOTES.key?(reason)

          @merge_request = merge_request
          @service_account = service_account
          @reason = reason
          @details = details
        end

        def execute
          unless permitted?
            log_failure('Fix loop not stopped: the service account cannot update the merge request.')
            return ServiceResponse.error(message: 'Service account cannot update the merge request')
          end

          @drafted = mark_as_draft if DRAFT_REASONS.include?(reason)
          return ServiceResponse.success if NO_REPEAT_REASONS.include?(reason) && latest_note_body == note_body

          note = create_note
          return ServiceResponse.success if note.persisted?

          log_failure('Fix loop note not created.', note.errors)
          ServiceResponse.error(message: note.errors.full_messages.join(', '))
        end

        private

        attr_reader :merge_request, :service_account, :reason, :details, :drafted

        # The account writes as itself, without the identity of a human, so it needs the permission itself.
        def permitted?
          Ability.allowed?(service_account, :update_merge_request, merge_request, composite_identity_check: false)
        end

        # Returns false when the merge request is still not a draft.
        def mark_as_draft
          # The job loaded the merge request before the checks, and its lock_version can be old by now. A replica
          # can still have the old one.
          ::Gitlab::Database::LoadBalancing::SessionMap.current(merge_request.load_balancer).use_primary do
            merge_request.reset
          end
          return true if merge_request.draft?

          ::MergeRequests::UpdateService.new(
            project: merge_request.target_project,
            current_user: service_account,
            params: { wip_event: 'draft' }
          ).execute(merge_request)
          return true if merge_request.errors.empty?

          log_failure('Fix loop could not mark the merge request as a draft.', merge_request.errors)
          false
        end

        def latest_note_body
          merge_request.notes.user.authored_by(service_account).order_created_at_id_desc.first&.note
        end

        def create_note
          # The verdict of a review can carry the id of the review session in the job context. The note does not
          # belong to that session.
          ::Gitlab::ApplicationContext.with_context(duo_workflow_id: nil) do
            ::Notes::CreateService.new(
              merge_request.target_project, service_account, note: note_body, noteable: merge_request
            ).execute
          end
        end

        def note_body
          send(NOTES.fetch(reason), author_reference).lstrip # rubocop:disable GitlabSecurity/PublicSend -- NOTES lists the private methods, and initialize rejects any other reason
        end
        strong_memoize_attr :note_body

        # A service account can be the author, and a mention could start its flows. The note still tells why.
        def author_reference
          author = merge_request.author
          author.human? ? author.to_reference : ''
        end

        def max_fix_runs_note(author)
          count = details[:max_fix_runs]
          # A code span, so the name of the reviewer is never a mention.
          message = format(
            ns_(
              'AiFlowTriggers|%{author} %{reviewer} requested changes after %{count} fix run, the limit of ' \
                '`max_fix_runs` in `%{path}`. No fix run starts.',
              'AiFlowTriggers|%{author} %{reviewer} requested changes after %{count} fix runs, the limit of ' \
                '`max_fix_runs` in `%{path}`. No fix run starts.',
              count
            ),
            author: author, reviewer: "`#{details[:reviewer].username}`", count: count, path: Config::PATH
          )

          stop_note(message)
        end

        # When the run has a progress note, that note shows the error.
        def fix_run_not_started_note(author)
          stop_note(format(s_('AiFlowTriggers|%{author} The fix run did not start, so the fix loop stops.'),
            author: author))
        end

        # A fix run that finds no change to make also ends without a push.
        def fix_run_without_push_note(author)
          fix_run = details[:fix_run]
          message = case fix_run.status_name
                    when :failed
                      s_('AiFlowTriggers|%{author} %{link_start}The fix run%{link_end} failed before it pushed a ' \
                        'fix, so no new review starts and the fix loop stops.')
                    when :stopped
                      s_('AiFlowTriggers|%{author} A user stopped %{link_start}the fix run%{link_end} before it ' \
                        'pushed a fix, so no new review starts and the fix loop stops.')
                    else
                      s_('AiFlowTriggers|%{author} %{link_start}The fix run%{link_end} finished without a push, ' \
                        'so no new review starts and the fix loop stops.')
                    end
          stop_note(format(message, author: author, link_start: '[', link_end: "](#{fix_run.web_url})"))
        end

        def stop_note(message)
          draft_state = if drafted
                          s_('AiFlowTriggers|This merge request is now a draft.')
                        else
                          s_('AiFlowTriggers|The fix loop could not mark this merge request as a draft.')
                        end

          "#{message} #{draft_state}\n\n#{next_step}"
        end

        def invalid_config_note(author)
          message = format(
            s_('AiFlowTriggers|%{author} No fix run starts, because the `review` key in `%{path}` is not valid:'),
            author: author, path: Config::PATH
          )

          [message, '', *Array(details[:errors]).map { |error| "- #{error}" }].join("\n")
        end

        def approved_note(author)
          count = details[:fix_runs]
          reviewer = "`#{details[:reviewer].username}`"

          if count == 0
            return format(s_('AiFlowTriggers|%{author} %{reviewer} approved this merge request without a fix run. ' \
              'The merge request is ready for the final review.'), author: author, reviewer: reviewer)
          end

          format(
            ns_(
              'AiFlowTriggers|%{author} %{reviewer} approved this merge request after %{count} fix run. The fix ' \
                'loop ends, and the merge request is ready for the final review.',
              'AiFlowTriggers|%{author} %{reviewer} approved this merge request after %{count} fix runs. The fix ' \
                'loop ends, and the merge request is ready for the final review.',
              count
            ),
            author: author, reviewer: reviewer, count: count
          )
        end

        def next_step
          s_('AiFlowTriggers|Read the review threads and decide the next step. When you mark the merge request ' \
            'as ready, the next request for changes starts a new fix loop.')
        end

        def log_failure(message, errors = nil)
          payload = { message: message, merge_request_id: merge_request.id, reason: reason }
          payload[:errors] = errors.full_messages.join(', ') if errors

          ::Gitlab::AppJsonLogger.warn(build_structured_payload(**payload))
        end
      end
    end
  end
end
