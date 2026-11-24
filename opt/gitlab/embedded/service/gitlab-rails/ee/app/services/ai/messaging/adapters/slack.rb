# frozen_string_literal: true

module Ai
  module Messaging
    module Adapters
      class Slack < Base
        include ::Ai::Messaging::UiChatLog
        include ::Gitlab::ExclusiveLeaseHelpers

        InstallationNotFoundError = Class.new(StandardError)

        FEEDBACK_ACTION_ID = 'duo_feedback'

        MONOLOGUE_DETAILS_MAX_LENGTH = 1500

        MONOLOGUE_TITLE_MAX_LENGTH = 120

        # Slack rejects an edit whose `text` is over 4,000 bytes once it has escaped &, < and >
        # (msg_too_long). Kept below that for headroom.
        TEXT_MAX_BYTES = 3_500

        TEXT_OMISSION = '…'

        # Slack rejects a markdown block over 12,000 characters. Kept below that for headroom.
        ANSWER_MAX_LENGTH = 11_500

        # Only needs to outlast one write; each holder re-reads the session, so it stays correct after expiry.
        PROGRESS_MESSAGE_LEASE_TTL = 30.seconds

        # How long the card's ts is kept so later updates can edit it. Only needs to outlast a running
        # delegated session; once it expires, an update posts a fresh card.
        CHILD_CARD_REFERENCE_TTL = 1.day

        # Any other write to the card takes about one Slack call, so the outcome waits that out rather
        # than spending one of CallbackWorker's few retries on it.
        CHILD_CARD_OUTCOME_LOCK_RETRIES = 10
        CHILD_CARD_OUTCOME_LOCK_SLEEP = 0.2.seconds

        MESSAGE_LOCK_SLEEP = 0.1.seconds

        # Kept under a second: the approval click renders inside Slack's 3-second interaction window.
        PROGRESS_LOCK_RETRIES = 9

        # The answer is the one write that must land, so it waits out a few progress writes.
        DELIVERY_LOCK_RETRIES = 50

        # A decided card shows until the resumed run adds to the log; a live one only while paused.
        ApprovalState = Data.define(:pending, :paused, :decision) do
          def card?
            pending.present? && (paused || decision.present?)
          end

          def awaiting?
            paused && decision.nil?
          end
        end

        # Cancelled maps to complete since Slack has no cancelled state
        TODO_PLAN_STATUSES = {
          'completed' => 'complete',
          'cancelled' => 'complete',
          'in_progress' => 'in_progress',
          'pending' => 'pending'
        }.freeze

        def self.adapter_key
          'slack'
        end

        def self.supports_live_progress?
          true
        end

        def self.private_to_invoker?
          true
        end

        def self.relays_child_sessions?
          true
        end

        # Async path: reconstructed from persisted callback context by CallbackWorker.
        # Only deliver_result, deliver_error, and lifecycle hooks are called on this instance.
        def self.from_callback_context(ctx)
          new(
            team_id: ctx['team_id'],
            channel_id: ctx['channel_id'],
            thread_ts: ctx['thread_ts'],
            message_ts: ctx['message_ts'],
            user_id: ctx['user_id']
          )
        end

        # Sync path: constructed by the caller (AppMentionedService) with full event state.
        # `duo_group_context` holds what the replies for a workspace's Duo group need (`slack_duo_group`).
        def initialize(team_id:, channel_id:, thread_ts:, message_ts:, user_id:, duo_group_context: {})
          @team_id = team_id
          @channel_id = channel_id
          @thread_ts = thread_ts
          @message_ts = message_ts
          @user_id = user_id
          @duo_group_context = duo_group_context
        end

        def build_callback_context
          {
            'team_id' => @team_id,
            'channel_id' => @channel_id,
            'thread_ts' => @thread_ts,
            'message_ts' => @message_ts,
            'user_id' => @user_id
          }.merge(@duo_group_context.stringify_keys)
        end

        # Earliest user-visible acknowledgement, fired synchronously before the
        # workflow exists: a rotating status indicator via assistant.threads.setStatus.
        # Slack clears the status automatically once the first real message is
        # posted (by on_progress, or by deliver_result if on_progress never fires).
        def on_request_received
          messages = loading_messages
          slack_api.set_status(
            channel: @channel_id,
            thread_ts: @thread_ts,
            status: messages.first,
            loading_messages: messages
          )
        rescue StandardError => e
          track_slack_exception(e, build_callback_context)
        end

        # Records context only; posting no message here lets the on_request_received
        # status indicator keep spinning until on_progress posts the first real
        # content (or deliver_result posts the answer if on_progress never fires).
        #
        # Idempotent: CallbackWorker is at-least-once.
        def on_flow_started(callback_context:, workflow:)
          callback_context['session_url'] = workflow.web_url
          callback_context['workflow_id'] = workflow.id
          workflow.merge_messaging_callback_context!(callback_context.slice('session_url', 'workflow_id').compact)
        rescue StandardError => e
          track_slack_exception(e, callback_context)
        end

        # workflow: nil -- sync failure before a workflow exists.
        # workflow: present -- async failure, either before on_flow_started (no message posted yet) or after it.
        def on_flow_failed(callback_context:, error:, workflow: nil)
          slack_api.add_reaction(channel: callback_context['channel_id'], name: 'x',
            timestamp: callback_context['message_ts'])

          # Surface the error, plus the session link so the failure can be
          # investigated in GitLab:
          #   * status_ts present -- a progress message exists; edit it with the error.
          #   * workflow but no progress message -- post a threaded reply with the error.
          #   * no workflow (sync failure) -- nothing to link; send an ephemeral error.
          #     An ephemeral is not a thread reply, so it does not clear the
          #     on_request_received status; clear it afterwards or it spins for 2 minutes.
          text = error_text(error, callback_context)
          unless workflow
            deliver_error(callback_context: callback_context, error: error)
            return slack_api.set_status(channel: callback_context['channel_id'],
              thread_ts: callback_context['thread_ts'], status: '')
          end

          begin
            with_message_lock(workflow, retries: DELIVERY_LOCK_RETRIES) do
              surface_flow_error(callback_context, workflow, text)
            end
          rescue FailedToObtainLockError
            # Nothing retries a failure, so it goes out unlocked rather than not at all.
            surface_flow_error(callback_context, workflow, text)
          end
        rescue StandardError => e
          track_slack_exception(e, callback_context)
        end

        # Returns false only when a card is owed and did not land, so CallbackWorker
        # can raise for a Sidekiq retry; nothing else re-fires during the pause.
        def on_approval_required(callback_context:, workflow:)
          return true unless Feature.enabled?(:slack_duo_api_flow, workflow.resource_parent&.root_ancestor)
          return true unless workflow.tool_call_approval_required?

          pending = ::Ai::DuoWorkflows::PendingToolApproval.for(workflow)
          return true unless pending
          return true if callback_context['pending_approval'] == pending.fingerprint

          return false unless show_progress_before_approval(workflow, callback_context)

          workflow.merge_messaging_callback_context!('pending_approval' => pending.fingerprint)
          true
        rescue StandardError => e
          track_slack_exception(e, callback_context)
          false
        end

        # Called on the click, since no progress tick arrives until the runtime picks the resumed run up.
        def on_approval_resolved(callback_context:, workflow:)
          return false if callback_context['status_ts'].blank?

          render_progress(workflow.latest_ui_chat_log, callback_context, workflow).present?
        end

        def on_progress(delta:, callback_context:, workflow:)
          # A tool-only checkpoint changes nothing visible; skipping it saves
          # rate-limit budget and keeps a plan the user expanded from collapsing.
          return unless delta.new_messages.any? { |message| renders_progress?(message) }

          render_progress(delta.messages, callback_context, workflow)
        rescue StandardError => e
          track_slack_exception(e, callback_context)
        end

        # Edits the message on_progress already posted, or posts a fresh threaded
        # reply if it never did, so the whole run reads as one message.
        #
        # Slack errors are tracked, never raised: the client reports API and HTTP failures
        # as an `ok: false` response, so `ok` is what tells CallbackWorker the answer landed.
        def deliver_result(callback_context:, message:, workflow:)
          blocks = result_blocks(message, workflow, callback_context)

          with_message_lock(workflow, retries: DELIVERY_LOCK_RETRIES) do
            refresh_status_ts(callback_context, workflow)

            if callback_context['status_ts']
              update_result_message(callback_context, message, blocks)
            else
              post_result_message(callback_context, message, blocks)
            end
          end
        rescue StandardError => e
          track_slack_exception(e, callback_context)
          false
        end

        # Posts an ephemeral error message visible only to the requesting user.
        # Best-effort: errors are tracked, never raised, and nothing re-attempts this
        # delivery -- unlike deliver_result, there is no answer at stake.
        # Threads the error into an existing thread; a top-level mention gets
        # channel-root placement to maximise visibility of the private ephemeral.
        def deliver_error(callback_context:, error:)
          in_existing_thread = callback_context['thread_ts'].present? &&
            callback_context['thread_ts'] != callback_context['message_ts']
          thread_ts = in_existing_thread ? callback_context['thread_ts'] : nil

          slack_api.post_ephemeral(
            channel: callback_context['channel_id'],
            user: callback_context['user_id'],
            text: error_text(error, callback_context),
            thread_ts: thread_ts
          )
        rescue StandardError => e
          track_slack_exception(e, callback_context)
        end

        # The delegated session is a normal project session, unlike the Slack session
        # itself, so its link can go in the shared message.
        def render_child_card(callback_context:, child:, outcome: nil)
          upsert_child_card(callback_context, child, outcome) == :rendered
        end

        # The card's final state alone would be an edit to an earlier message, which notifies
        # nobody, so the outcome is also posted as a reply.
        def deliver_child_result(callback_context:, child:, message:, error:)
          # Retried while another job writes the card, so the card cannot be left on an earlier frame.
          return false if upsert_child_card(callback_context, child, error || :finished) == :busy

          text = child_result_text(child, message, error)
          post_result_message(callback_context, text, [markdown_block(fit_answer(text))])
        rescue StandardError => e
          track_slack_exception(e, callback_context)
          false
        end

        private

        # On the Duo group path, which setting refused is only worked out once the platform refused.
        def start_workhorse_flow(bundle, ctx)
          result = super
          if result.reason == :cannot_create_workflow_pipeline && @duo_group_context.present?
            ctx['duo_group_refusal'] = ::Integrations::SlackWorkspace::DuoMentionExecutionContainerResolver.refusal(
              bundle.container, bundle.current_user
            )
          end

          result
        end

        # Rotating strings shown via assistant.threads.setStatus for the whole run.
        # Slack auto-rotates through these as a loading animation and clears them
        # when the first real message is posted. When the agent produces no todo
        # list and no monologue, this status is the only progress signal the user
        # sees, so the strings describe the work generally rather than startup.
        # Built at call time (not a constant) so translations resolve dynamically.
        def loading_messages
          [
            s_('DuoSlack|is working on your request…'),
            s_('DuoSlack|is thinking it through…')
          ]
        end

        def show_progress_before_approval(workflow, callback_context)
          messages =
            if callback_context['status_ts']
              workflow.latest_ui_chat_log
            else
              delta = ::Ai::DuoWorkflows::ProgressReader.new
                .delta_since(workflow, cursor: callback_context['progress_cursor'])
              delta.new_messages.any? { |m| renders_progress?(m) } ? delta.messages : []
            end

          render_progress(messages, callback_context, workflow)
        end

        # Every writer of the progress message (ticks, the pause, the click) renders here
        # from the same state, so whichever write lands last is still correct.
        def render_progress(messages, callback_context, workflow)
          with_message_lock(workflow, retries: PROGRESS_LOCK_RETRIES) do
            # Read under the lock: this job's copy can predate the pause, the decision, the answer
            # or a message another job opened.
            state = workflow.messaging_state_on_primary
            paused = state[:status] == :tool_call_approval_required

            next if state[:context]['delivered_at']
            # A job loaded just before the pause stands down; the pause renders the card from the full log.
            next if paused && !workflow.tool_call_approval_required?

            approval = current_approval(workflow, messages, paused: paused, context: state[:context])
            blocks = progress_blocks(messages, awaiting_approval: approval.awaiting?)
            blocks.concat(approval_blocks(approval, workflow, callback_context['user_id']))
            next if blocks.empty?

            text = approval_text(approval) || progress_fallback_text(messages)
            status_ts = state[:context]['status_ts'] || callback_context['status_ts']
            write_progress_message(workflow, callback_context, status_ts, text, blocks)
          end
        rescue FailedToObtainLockError
          # Another write is landing; the next tick, or the answer, renders after it.
          nil
        end

        def write_progress_message(workflow, callback_context, status_ts, text, blocks)
          if status_ts
            response = slack_api.update_message(
              channel: callback_context['channel_id'],
              ts: status_ts,
              text: text,
              blocks: blocks
            )
            return status_ts if response['ok']
            # A deleted progress message fails every edit, so the run gets a fresh one.
            return unless response['error'] == 'message_not_found'
          end

          open_progress_message(workflow, callback_context, text, blocks)
        end

        # A paused copy reads the request from its full log, since a caller may pass only this
        # turn's messages; otherwise the caller's log decides, so a decided card shows until the run adds to it.
        def current_approval(workflow, messages, paused:, context:)
          log = workflow.tool_call_approval_required? ? workflow.latest_ui_chat_log : messages
          pending = ::Ai::DuoWorkflows::PendingToolApproval.from_log(log)

          ApprovalState.new(pending: pending, paused: paused, decision: answered_decision(context, pending))
        end

        def answered_decision(context, pending)
          return unless pending && context['answered_approval'] == pending.fingerprint

          ToolApprovalCard::DECISIONS.find { |decision| decision.to_s == context['answered_decision'] }
        end

        def progress_blocks(messages, awaiting_approval:)
          todos = latest_todos(messages)
          monologue = latest_monologue(messages)
          return [] if todos.empty? && monologue.blank?

          title = progress_plan_title(todos, awaiting_approval: awaiting_approval)
          [plan_block(todos, title: title, monologue: monologue)]
        end

        def open_progress_message(workflow, callback_context, text, blocks)
          response = slack_api.post_message(
            channel: callback_context['channel_id'],
            thread_ts: callback_context['thread_ts'],
            text: text,
            blocks: blocks
          )
          return unless response['ok']

          workflow.merge_messaging_callback_context!('status_ts' => response['ts'])
          response['ts']
        end

        # Every write to the run's message holds this lock, so the progress message and the
        # answer never land as two messages, and a late progress edit never covers the answer.
        def with_message_lock(workflow, retries:, &block)
          in_lock("duo_slack_progress_message:#{workflow.id}",
            ttl: PROGRESS_MESSAGE_LEASE_TTL, retries: retries, sleep_sec: MESSAGE_LOCK_SLEEP, &block)
        end

        def surface_flow_error(callback_context, workflow, text)
          refresh_status_ts(callback_context, workflow)

          if callback_context['status_ts']
            slack_api.update_message(
              channel: callback_context['channel_id'],
              ts: callback_context['status_ts'],
              text: text,
              blocks: [markdown_block(text)]
            )
          else
            callback_context['session_url'] = workflow.web_url
            post_threaded_reply(callback_context, text, blocks: [markdown_block(text)])
          end

          post_session_link_ephemeral(callback_context)
        end

        # This job's copy of the context can predate a progress message another job opened.
        def refresh_status_ts(callback_context, workflow)
          status_ts = workflow.messaging_callback_context_on_primary['status_ts']
          callback_context['status_ts'] = status_ts if status_ts
        end

        def final_todos(workflow)
          latest_todos(workflow.latest_ui_chat_log)
        end

        # The single source of truth for the final message blocks, so the post and
        # edit paths in deliver_result can never drift (that drift is what dropped
        # the feedback buttons from plan-less replies).
        def result_blocks(message, workflow, callback_context)
          todos = final_todos(workflow)
          blocks = []
          blocks << settled_plan_block(todos) if todos.any?
          blocks << markdown_block(fit_answer(message))
          blocks << attribution_block(workflow)
          blocks.concat(feedback_blocks(callback_context))
          blocks
        end

        def attribution_block(workflow)
          model = model_display_name(workflow)
          text = model.present? ? format(s_('DuoSlack|GitLab Duo · %{model}'), model: model) : _('GitLab Duo')

          { type: 'context', elements: [{ type: 'plain_text', text: text }] }
        end

        # The metadata holds a gateway ref (claude_sonnet_4_6), which ModelMetadata maps to the
        # catalog name, or returns as is when the catalog has no match.
        def model_display_name(workflow)
          metadata = workflow.model_metadata_json.presence && Gitlab::Json.safe_parse(workflow.model_metadata_json)
          ref = metadata['name'].to_s if metadata.is_a?(Hash)
          return if ref.blank?

          ::Ai::DuoWorkflows::ModelMetadata.for([ref])[ref].name
        # A raise here would drop the whole answer, so any failure only loses the model name.
        rescue StandardError => e
          Gitlab::ErrorTracking.track_exception(e, workflow_id: workflow.id)
          nil
        end

        # A run can end mid-plan and nothing edits the message afterwards. Slack keeps a plan
        # spinning while any task is pending or in progress, so an open task ends as not done.
        def settled_plan_block(todos)
          plan_block(todos, title: result_plan_title(todos)).tap do |plan|
            plan[:tasks].each { |task| task[:status] = 'error' unless task[:status] == 'complete' }
          end
        end

        def fit_answer(message)
          return message if message.length <= ANSWER_MAX_LENGTH

          shortened = message[0, ANSWER_MAX_LENGTH]
          paragraph_end = shortened.rindex("\n\n")
          shortened = shortened[0, paragraph_end] if paragraph_end && paragraph_end > ANSWER_MAX_LENGTH / 2

          note = s_('DuoSlack|Answer shortened to fit in Slack. The full answer is in the GitLab session.')
          "#{shortened.rstrip}\n\n_#{note}_"
        end

        def result_plan_title(todos)
          done = todos.count { |todo| TODO_PLAN_STATUSES[todo['status'].to_s] == 'complete' }
          return s_('DuoSlack|Plan complete') if done == todos.size

          format(s_('DuoSlack|Plan (%{done}/%{total} done)'), done: done, total: todos.size)
        end

        def update_result_message(callback_context, message, blocks)
          text = truncate_text(message)

          response = slack_api.update_message(
            channel: callback_context['channel_id'],
            ts: callback_context['status_ts'],
            text: text,
            blocks: blocks
          )
          return true if response['ok']

          # Blocks rejected (fit_answer already handles length): re-edit with
          # plain text, which is cut at the text limit.
          slack_api.update_message(
            channel: callback_context['channel_id'],
            ts: callback_context['status_ts'],
            text: text,
            blocks: []
          )['ok']
        end

        def post_result_message(callback_context, message, blocks)
          return true if post_threaded_reply(callback_context, truncate_text(message), blocks: blocks)['ok']

          # Blocks rejected (fit_answer already handles length): a new message without blocks
          # takes the answer as plain text. Only chat.update rejects on length; chat.postMessage
          # accepts text far past the edit limit.
          post_threaded_reply(callback_context, message)['ok']
        end

        # Spends the byte budget character by character, since cutting at a byte count and
        # re-measuring does not converge: dropping one raw byte can drop five escaped ones.
        def truncate_text(message)
          return message if slack_escaped_bytesize(message) <= TEXT_MAX_BYTES

          budget = TEXT_MAX_BYTES - TEXT_OMISSION.bytesize
          size = 0
          kept = message.each_char.take_while { |char| (size += slack_escaped_bytesize(char)) <= budget }
          "#{kept.join}#{TEXT_OMISSION}"
        end

        def slack_escaped_bytesize(text)
          text.bytesize + (text.count('&') * 4) + (text.count('<>') * 3)
        end

        # block_id is freshly generated on every render: Slack requires a new
        # block_id for a plan update to take effect on an edited message.
        def plan_block(todos, title:, monologue: nil)
          {
            type: 'plan',
            block_id: SecureRandom.hex(8),
            title: title,
            tasks: plan_tasks(todos, monologue: monologue)
          }
        end

        def plan_tasks(todos, monologue:)
          return [monologue_task(monologue)] if todos.empty?

          active_index = active_task_index(todos)

          todos.each_with_index.map do |todo, index|
            task = {
              task_id: "task_#{index}",
              title: todo['description'].to_s,
              status: TODO_PLAN_STATUSES.fetch(todo['status'].to_s)
            }
            task[:details] = monologue_details(monologue) if monologue && index == active_index
            task
          end
        end

        def monologue_task(monologue)
          {
            task_id: 'task_0',
            title: monologue.squish.truncate(MONOLOGUE_TITLE_MAX_LENGTH, separator: ' ', omission: '…'),
            status: 'in_progress'
          }
        end

        def active_task_index(todos)
          todos.index { |todo| todo['status'].to_s == 'in_progress' } ||
            todos.index { |todo| todo['status'].to_s == 'pending' } ||
            (todos.size - 1)
        end

        def monologue_details(monologue)
          {
            type: 'rich_text',
            block_id: SecureRandom.hex(8),
            elements: [{ type: 'rich_text_section', elements: [{ type: 'text', text: monologue }] }]
          }
        end

        def progress_plan_title(todos, awaiting_approval:)
          if todos.empty?
            return awaiting_approval ? s_('DuoSlack|Waiting for approval') : s_('DuoSlack|Working on your request…')
          end

          counts = {
            done: todos.count { |todo| TODO_PLAN_STATUSES[todo['status'].to_s] == 'complete' },
            total: todos.size
          }

          if awaiting_approval
            format(s_('DuoSlack|Waiting for approval (%{done}/%{total} done)'), counts)
          else
            format(s_('DuoSlack|Working on your request… (%{done}/%{total} done)'), counts)
          end
        end

        # Shown in notifications, so it must not read like the answer.
        def progress_fallback_text(messages)
          todos = latest_todos(messages)
          title = progress_plan_title(todos, awaiting_approval: false)
          return title if todos.empty?

          [title, todos[active_task_index(todos)]['description']].compact_blank.join("\n")
        end

        def latest_monologue(messages)
          content = latest_agent_content(messages)
          return if content.nil?

          CommonMarker.render_doc(content, :DEFAULT, %i[table strikethrough]).to_plaintext(:DEFAULT, 0)
            .gsub(/\n{2,}/, "\n").strip
            .truncate(MONOLOGUE_DETAILS_MAX_LENGTH, separator: ' ', omission: '…')
            .presence
        end

        def post_threaded_reply(callback_context, text, blocks: [])
          slack_api.post_message(
            channel: callback_context['channel_id'],
            thread_ts: callback_context['thread_ts'],
            text: text,
            blocks: blocks
          )
        end

        # Standard Markdown, ~12k char limit, translated natively by Slack.
        def markdown_block(message)
          { type: 'markdown', text: message }
        end

        # Sessions are private to the invoker, so the link is delivered as an
        # ephemeral message only they can see; in the shared reply it would 404
        # for everyone else. Best-effort: ephemerals are transient anyway and the
        # session stays reachable through the GitLab session list.
        def post_session_link_ephemeral(callback_context)
          url = callback_context['session_url']
          return if url.blank?

          link_text = s_('DuoSlack|View your session in GitLab')
          slack_api.post_ephemeral(
            channel: callback_context['channel_id'],
            user: callback_context['user_id'],
            text: "_<#{url}|#{link_text}>_",
            thread_ts: callback_context['thread_ts']
          )
        rescue StandardError => e
          track_slack_exception(e, callback_context)
        end

        def feedback_blocks(callback_context)
          workflow_id = callback_context['workflow_id']
          return [] if workflow_id.blank?

          [{
            type: 'context_actions',
            elements: [{
              type: 'feedback_buttons',
              action_id: FEEDBACK_ACTION_ID,
              positive_button: {
                text: { type: 'plain_text', text: s_('DuoSlack|Helpful') },
                accessibility_label: s_('DuoSlack|Mark this response as helpful'),
                value: "up:#{workflow_id}"
              },
              negative_button: {
                text: { type: 'plain_text', text: s_('DuoSlack|Not helpful') },
                accessibility_label: s_('DuoSlack|Mark this response as not helpful'),
                value: "down:#{workflow_id}"
              }
            }]
          }]
        end

        def approval_request_text(pending)
          flow_text = ToolApprovalCard.flow_request_text(pending)
          return flow_text if flow_text

          format(
            s_('DuoSlack|GitLab Duo needs your approval to run: %{tool_names}'),
            tool_names: pending.tool_names.uniq.map { |name| "`#{name}`" }.join(', ')
          )
        end

        # Only the requester can decide, so they are also the one named on a decided card.
        def approval_blocks(approval, workflow, requester_id)
          return [] unless approval.card?

          ToolApprovalCard.new(approval.pending, workflow_id: workflow.id, requester_id: requester_id)
            .blocks(decision: approval.decision, decided_by: approval.decision && requester_id)
        end

        def approval_text(approval)
          return ToolApprovalCard.outcome_text(approval.decision) if approval.decision

          approval_request_text(approval.pending) if approval.card?
        end

        def error_text(error, callback_context)
          case error
          when :namespace_not_configured
            preferences_url = ::Gitlab::Routing.url_helpers.profile_preferences_url

            format(
              s_("DuoSlack|Set your default Duo namespace in your " \
                "GitLab preferences (%{preferences_url}) to use Duo from Slack."),
              preferences_url: preferences_url
            )
          when :flow_not_enabled, :foundational_flows_disabled
            flow_not_enabled_text(error, callback_context)
          when :service_account_error
            s_("DuoSlack|Could not set up the service account for the flow. Contact your group owner.")
          when :workspace_project_error
            s_("DuoSlack|Could not set up the workspace project. " \
              "Check that you have access to the namespace and permission to create projects.")
          when :execute_workflow_failed
            s_("DuoSlack|Failed to start the GitLab Duo session. Try again.")
          when :flow_failed
            s_("DuoSlack|Something went wrong while running the task. Try again.")
          when :flow_stopped
            s_("DuoSlack|The session was stopped before it finished.")
          when :workflow_locked
            s_("DuoSlack|I'm still working on an earlier message in this thread. " \
              "Wait for that to finish, then mention me again.")
          when :forbidden, :cannot_create_workflow_pipeline, :usage_quota_exceeded, :usage_billing_forbidden,
            :flow_disabled_by_feature_flag
            access_error_text(error, callback_context)
          when :no_response
            s_("DuoSlack|The task completed but the agent didn't produce a response. " \
              "Check the session in GitLab for details.")
          when :delivery_failed
            s_("DuoSlack|The task completed, but I couldn't post the answer here. " \
              "Check the session in GitLab for the full response.")
          when :message_too_long
            format(
              s_("DuoSlack|Your message is too long for me to process " \
                "(the limit is about %{limit} characters). Shorten it and mention me again."),
              limit: ActiveSupport::NumberHelper.number_to_delimited(::Ai::DuoWorkflows::Workflow::GOAL_MAX_LENGTH)
            )
          else
            fallback_error_text(error, callback_context)
          end
        end

        def fallback_error_text(error, callback_context)
          duo_group_reply(error, callback_context) || s_("DuoSlack|Something went wrong. Try again.")
        end

        # The Duo group path (`slack_duo_group`) names the Duo group and who can fix the setting.
        def duo_group_reply(error, callback_context)
          DuoGroupReplies.text(error, callback_context) if callback_context['duo_group_path'].present?
        end

        # @return [Array] fallback text, blocks, and the frame: what the card shows, minus Slack's
        #   per-render block_ids, so an unchanged card is not edited again and the outcome is never
        #   replaced by an earlier one
        def child_card(child, outcome)
          name = child_display_name(child)
          messages = child.latest_ui_chat_log
          todos = latest_todos(messages)
          monologue = outcome ? nil : latest_monologue(messages)
          awaiting_approval = outcome.nil? && child.tool_call_approval_required?
          icon, label = child_card_status(
            outcome, running: todos.any? || monologue.present?, awaiting_approval: awaiting_approval
          )

          blocks = [{ type: 'section', text: { type: 'mrkdwn', text: "#{icon} *#{escape_mrkdwn(name)}* · #{label}" } }]

          if outcome
            blocks << settled_plan_block(todos) if todos.any?
          elsif todos.any? || monologue.present?
            title = progress_plan_title(todos, awaiting_approval: awaiting_approval)
            blocks << plan_block(todos, title: title, monologue: monologue)
          end

          blocks << {
            type: 'context',
            elements: [{ type: 'mrkdwn', text: "<#{child.web_url}|#{s_('DuoSlack|Open session in GitLab')}>" }]
          }

          digest = Digest::SHA256.hexdigest(Gitlab::Json.dump([name, label, todos, monologue]))
          frame = "#{outcome || :running}:#{digest}"

          ["#{escape_mrkdwn(name)}: #{label}", blocks, frame]
        end

        def child_card_status(outcome, running: false, awaiting_approval: false)
          case outcome
          when nil
            if awaiting_approval
              [':raised_hand:', s_('DuoSlack|Waiting for approval')]
            elsif running
              [':hourglass_flowing_sand:', s_('DuoSlack|Running')]
            else
              [':rocket:', s_('DuoSlack|Started')]
            end
          when :finished then [':white_check_mark:', s_('DuoSlack|Finished')]
          when :flow_stopped then [':black_square_for_stop:', s_('DuoSlack|Stopped')]
          else [':x:', s_('DuoSlack|Failed')]
          end
        end

        def child_display_name(child)
          child.foundational_flow&.translated_display_name ||
            child.title.presence ||
            child.workflow_definition.to_s.humanize
        end

        def child_result_text(child, message, error)
          name = child_display_name(child)

          if error == :flow_stopped
            format(s_('DuoSlack|**%{name}** was stopped before it finished.'), name: name)
          elsif error
            format(s_('DuoSlack|**%{name}** failed. [Open the session](%{url}) for details.'),
              name: name, url: child.web_url)
          elsif message.blank?
            format(s_('DuoSlack|**%{name}** finished without a response. [Open the session](%{url}) for details.'),
              name: name, url: child.web_url)
          else
            "#{format(s_('DuoSlack|**%{name}** finished:'), name: name)}\n\n#{message}"
          end
        end

        # Every write to the card holds one lock and reads the card's state inside it, so an
        # earlier frame can never land on top of the outcome. Only the outcome waits for it.
        #
        # @return [Symbol] :rendered, :busy while another job writes the card, or :failed
        def upsert_child_card(callback_context, child, outcome)
          retries = outcome ? CHILD_CARD_OUTCOME_LOCK_RETRIES : 0

          in_lock("#{child_card_key(child)}:write", ttl: PROGRESS_MESSAGE_LEASE_TTL.to_i,
            retries: retries, sleep_sec: CHILD_CARD_OUTCOME_LOCK_SLEEP) do
            write_child_card(callback_context, child, outcome)
          end
        rescue FailedToObtainLockError
          :busy
        rescue StandardError => e
          track_slack_exception(e, callback_context)
          :failed
        end

        def write_child_card(callback_context, child, outcome)
          ts, rendered_frame = child_card_state(child)
          # The outcome owns the card once it has rendered.
          return :rendered if outcome.nil? && child_card_settled?(rendered_frame)

          text, blocks, frame = child_card(child, outcome)
          return :rendered if ts && rendered_frame == frame

          result = ts ? edit_child_card(callback_context, ts, text, blocks) : :not_found
          result = post_child_card(callback_context, text, blocks) if result == :not_found
          return :failed unless result.is_a?(String)

          store_child_card_state(child, result, frame)
          :rendered
        end

        # @return [String, Symbol] the card's ts, :not_found or :failed
        def edit_child_card(callback_context, ts, text, blocks)
          response = slack_api.update_message(
            channel: callback_context['channel_id'], ts: ts, text: text, blocks: blocks
          )
          return ts if response['ok']

          # A deleted card fails every edit, so the session gets a fresh one.
          response['error'] == 'message_not_found' ? :not_found : :failed
        end

        # @return [String, Symbol] the new card's ts or :failed
        def post_child_card(callback_context, text, blocks)
          response = slack_api.post_message(
            channel: callback_context['channel_id'],
            thread_ts: callback_context['thread_ts'],
            text: text,
            blocks: blocks
          )

          response['ok'] ? response['ts'] : :failed
        end

        def child_card_key(child)
          "ai:messaging:slack:child_card:#{child.id}"
        end

        def child_card_frame_key(child)
          "#{child_card_key(child)}:frame"
        end

        # Separate keys rather than one MGET, which would cross slots on Redis Cluster.
        #
        # @return [Array(String, String)] the card's ts and the frame it last rendered
        def child_card_state(child)
          Gitlab::Redis::SharedState.with do |redis|
            [redis.get(child_card_key(child)), redis.get(child_card_frame_key(child))]
          end
        end

        def store_child_card_state(child, ts, frame)
          Gitlab::Redis::SharedState.with do |redis|
            redis.set(child_card_key(child), ts, ex: CHILD_CARD_REFERENCE_TTL.to_i)
            redis.set(child_card_frame_key(child), frame, ex: CHILD_CARD_REFERENCE_TTL.to_i)
          end
        end

        def child_card_settled?(frame)
          frame.present? && !frame.start_with?('running')
        end

        # Slack's mrkdwn format (as in ToolApprovalCard), not the Markdown that markdown_block takes.
        def escape_mrkdwn(text)
          text.to_s.gsub('&', '&amp;').gsub('<', '&lt;').gsub('>', '&gt;')
        end

        # Reasons CreateWorkflowService refuses a session for. namespace_path is
        # set on the context by Base#trigger; contexts persisted before that lack it,
        # and get whole sentences rather than a spliced-in fragment translators cannot inflect.
        def access_error_text(error, callback_context)
          duo_group_text = duo_group_reply(error, callback_context)
          return duo_group_text if duo_group_text

          namespace = callback_context['namespace_path']
          return unnamed_access_error_text(error) if namespace.blank?

          case error
          when :cannot_create_workflow_pipeline
            format(
              s_("DuoSlack|You need at least the Developer role in %{namespace} to use Duo from Slack. " \
                "Ask an Owner of that group, or change your default GitLab Duo namespace " \
                "in your preferences (%{preferences_url})."),
              namespace: namespace,
              preferences_url: ::Gitlab::Routing.url_helpers.profile_preferences_url
            )
          when :usage_quota_exceeded
            format(
              s_("DuoSlack|%{namespace} has run out of GitLab Duo credits. " \
                "Ask a group owner to check the usage and billing settings."),
              namespace: namespace
            )
          when :usage_billing_forbidden
            format(
              s_("DuoSlack|GitLab Duo usage billing is not available for %{namespace}. " \
                "Ask a group owner to check the GitLab Duo settings."),
              namespace: namespace
            )
          when :flow_disabled_by_feature_flag
            format(s_("DuoSlack|This flow is not available for %{namespace} yet."), namespace: namespace)
          else
            forbidden_text
          end
        end

        # Slack ignores project and subgroup flow settings, so the message names the
        # root group it checked; users otherwise toggle the flow in the wrong place.
        def flow_not_enabled_text(error, callback_context)
          namespace = callback_context['namespace_path']

          if namespace.blank?
            return format(
              s_("DuoSlack|The %{flow_name} flow is not turned on for your namespace. " \
                "Ask a group owner to turn it on in the GitLab Duo Agent Platform settings."),
              flow_name: callback_context['flow_name']
            )
          end

          message =
            if error == :foundational_flows_disabled
              s_("DuoSlack|Foundational flows are turned off in %{namespace}, your default GitLab Duo " \
                "namespace. Ask an Owner of %{namespace} to turn on Allow foundational flows and the " \
                "%{flow_name} flow in the GitLab Duo settings (%{settings_url}). To use a different group, " \
                "change your default GitLab Duo namespace in your preferences (%{preferences_url}).")
            else
              s_("DuoSlack|The %{flow_name} flow is turned off in %{namespace}, your default GitLab Duo " \
                "namespace. Ask an Owner of %{namespace} to turn it on in the GitLab Duo settings " \
                "(%{settings_url}). Turning it on for a project or subgroup is not enough. To use a " \
                "different group, change your default GitLab Duo namespace in your preferences " \
                "(%{preferences_url}).")
            end

          format(
            message,
            flow_name: callback_context['flow_name'],
            namespace: namespace,
            settings_url: callback_context['namespace_settings_url'],
            preferences_url: ::Gitlab::Routing.url_helpers.profile_preferences_url
          )
        end

        def unnamed_access_error_text(error)
          case error
          when :cannot_create_workflow_pipeline
            format(
              s_("DuoSlack|You need at least the Developer role in your default GitLab Duo namespace " \
                "to use Duo from Slack. Ask an Owner of that group, or change your default GitLab Duo " \
                "namespace in your preferences (%{preferences_url})."),
              preferences_url: ::Gitlab::Routing.url_helpers.profile_preferences_url
            )
          when :usage_quota_exceeded
            s_("DuoSlack|Your default GitLab Duo namespace has run out of GitLab Duo credits. " \
              "Ask a group owner to check the usage and billing settings.")
          when :usage_billing_forbidden
            s_("DuoSlack|GitLab Duo usage billing is not available for your default GitLab Duo namespace. " \
              "Ask a group owner to check the GitLab Duo settings.")
          when :flow_disabled_by_feature_flag
            s_("DuoSlack|This flow is not available for your default GitLab Duo namespace yet.")
          else
            forbidden_text
          end
        end

        def forbidden_text
          s_("DuoSlack|You don't have access to Duo in this namespace, or it has run out of " \
            "GitLab Duo credits. Ask a group owner to check the Duo Agent Platform settings.")
        end

        def slack_api
          @slack_api ||= begin
            installation = SlackIntegration.with_bot.find_by_team_id(@team_id)
            raise InstallationNotFoundError, "No Slack installation found for team #{@team_id}" unless installation

            ::Slack::API.new(installation)
          end
        end

        def track_slack_exception(exception, callback_context)
          Gitlab::ErrorTracking.track_exception(exception,
            slack_team_id: callback_context['team_id'],
            channel_id: callback_context['channel_id']
          )
        end
      end
    end
  end
end
