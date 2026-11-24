# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class WorkflowCheckpointEventPresenter < Gitlab::View::Presenter::Delegated
      include Gitlab::Utils::StrongMemoize

      presents ::Ai::DuoWorkflows::Checkpoint, as: :event

      DuoMessage = Struct.new(:content, :message_type, :message_sub_type, :status, :tool_info,
        :timestamp, :correlation_id, :role, :message_id, :additional_context,
        :component_name, :subsession_id, :thread_ts, :parent_ts, :alternative_count, keyword_init: true)

      # Categories that are internal metadata envelopes, not user-visible context
      # items, and therefore not registered in AiAdditionalContextCategory enum.
      INTERNAL_CONTEXT_CATEGORIES = %w[orbit_context permissions_form_context duo_chat_command
        dashboard_context].freeze

      # thread_ts/parent_ts/alternative_count are stamped during blob reconstruction,
      # so they are nil on the header path -- it holds no per-message lineage to
      # attribute. alternative_count is also nil on messages that anchor no turn.
      MESSAGE_KEYS = %w[
        content message_type message_sub_type status tool_info timestamp
        correlation_id role message_id additional_context component_name subsession_id
        thread_ts parent_ts alternative_count
      ].freeze

      # Resolves #checkpoint for a page of events, yielding each with its checkpoint.
      # A workflow's rows share one blob query and decode each blob once, as the
      # internal checkpoint list does, instead of rebuilding every row from scratch.
      def self.batch_checkpoints(presenters)
        from_blobs, legacy = presenters.partition do |presenter|
          presenter.workflow.incremental_blob_gate.read?
        end
        legacy.each { |presenter| yield presenter, presenter.checkpoint }

        from_blobs.group_by { |presenter| presenter.workflow.object_id }.each_value do |rows|
          blobs_by_thread_ts = rows.first.workflow.blobs_by_thread_ts_for(rows.map(&:event))
          decoded = {}
          rows.each { |presenter| yield presenter, presenter.checkpoint_from(blobs_by_thread_ts, decoded) }
        end
      end

      # Resolves #duo_messages for a page of events, yielding each with its
      # messages, from page-level queries instead of several per row.
      def self.batch_duo_messages(presenters, &block)
        # Splitting the page below reads each workflow's newest header; load them all at once.
        ::Ai::DuoWorkflows::Workflow.prime_latest_checkpoint_headers(
          presenters.map(&:workflow).uniq(&:object_id)
        )

        from_blobs, legacy = presenters.partition do |presenter|
          presenter.workflow.incremental_blob_gate.read?
        end
        legacy.each { |presenter| yield presenter, presenter.duo_messages }
        return if from_blobs.empty?

        batch_duo_messages_from_blobs(from_blobs, &block)
      end

      # Rows that read from blobs. The latest checkpoint of a workflow reads through
      # the history cache, and the rest fold their whole chain.
      def self.batch_duo_messages_from_blobs(presenters)
        workflows = presenters.map(&:workflow).uniq(&:object_id)
        ::Ai::DuoWorkflows::Workflow.prime_message_history_context(workflows)

        cache = ::Gitlab::DuoWorkflow::ChatHistoryCache.new(presenters.select(&:cache_chat_history?))
        cached, uncached = presenters.partition { |presenter| cache.covers?(presenter) }

        chain_thread_ts = uncached.flat_map do |presenter|
          presenter.workflow.full_ancestor_thread_ts(presenter)
        end
        blobs_by_workflow_id = ::Ai::DuoWorkflows::Workflow
          .history_blobs_for_workflows(workflows, (chain_thread_ts + cache.thread_ts_to_load).uniq, 'ui_chat_log')

        uncached.each do |presenter|
          blobs_by_thread_ts = (blobs_by_workflow_id[presenter.workflow_id] || []).group_by(&:thread_ts)
          yield presenter, presenter.duo_messages_from(blobs_by_thread_ts)
        end

        cached.each do |presenter|
          history = cache.history(presenter, blobs_by_workflow_id[presenter.workflow_id] || [])
          yield presenter, presenter.build_duo_messages(history)
        end
        cache.write
      end
      private_class_method :batch_duo_messages_from_blobs

      # Newest todo_write message with todos. tool_info sits inside the compressed blob
      # payload, so this searches the folded #duo_messages rather than querying for it.
      def self.latest_todo_duo_message(messages)
        messages.reverse_each.find { |message| todo_message?(message) }
      end

      # Mirrors WorkflowUtils.findLatestTodoToolInfo on the frontend.
      def self.todo_message?(message)
        tool_info = message.tool_info
        return false unless tool_info.is_a?(Hash) && tool_info['name'] == 'todo_write'

        args = tool_info['args']
        args.is_a?(Hash) && args['todos'].present?
      end
      private_class_method :todo_message?

      # Resolves #last_duo_message for a page of events, yielding each with its
      # message, from page-level queries instead of two per row.
      def self.batch_last_duo_messages(presenters)
        ::Ai::DuoWorkflows::Workflow.prime_latest_checkpoint_headers(
          presenters.map(&:workflow).uniq(&:object_id)
        )

        from_blobs, legacy = presenters.partition do |presenter|
          presenter.workflow.incremental_blob_gate.read?
        end
        legacy.each { |presenter| yield presenter, presenter.last_duo_message }
        return if from_blobs.empty?

        workflows = from_blobs.map(&:workflow).uniq(&:object_id)
        newest_blobs = ::Ai::DuoWorkflows::Workflow.newest_channel_blobs_for(workflows, 'ui_chat_log')
        prime_chains_beyond_parent(from_blobs, newest_blobs)

        from_blobs.each do |presenter|
          yield presenter, last_duo_message_from_newest(presenter, newest_blobs[presenter.workflow_id])
        end
      end

      # The newest blob is almost always the row's checkpoint or its parent; load the
      # ancestor chain only for the rows where it is further up.
      def self.prime_chains_beyond_parent(presenters, newest_blobs)
        far = presenters.select do |presenter|
          blob = newest_blobs[presenter.workflow_id]
          blob && !near?(presenter, blob)
        end
        return if far.empty?

        ::Ai::DuoWorkflows::Workflow.prime_checkpoint_header_rows_for(far.map(&:workflow).uniq(&:object_id))
      end
      private_class_method :prime_chains_beyond_parent

      def self.last_duo_message_from_newest(presenter, blob)
        return unless blob
        # Off this row's chain (a sibling branch, or firstCheckpoint): read along the chain instead.
        return presenter.last_duo_message unless on_chain?(presenter, blob)

        presenter.last_duo_message_from(::Gitlab::DuoWorkflow::ChannelValuesReconstructor.decode(blob.data))
      end
      private_class_method :last_duo_message_from_newest

      def self.near?(presenter, blob)
        blob.thread_ts == presenter.thread_ts || blob.thread_ts == presenter.parent_ts
      end
      private_class_method :near?

      def self.on_chain?(presenter, blob)
        near?(presenter, blob) || presenter.workflow.full_ancestor_thread_ts(presenter).include?(blob.thread_ts)
      end
      private_class_method :on_chain?

      def self.build_duo_message(message)
        msg = message.slice(*MESSAGE_KEYS)

        if msg['additional_context'].is_a?(Array)
          msg['additional_context'] = msg['additional_context'].reject do |ctx|
            INTERNAL_CONTEXT_CATEGORIES.include?(ctx['category'])
          end
        end

        DuoMessage.new(**msg.symbolize_keys)
      end

      def workflow_status
        event.workflow.status
      end

      def workflow_goal
        event.workflow.goal
      end

      def workflow_definition
        event.workflow.workflow_definition
      end

      def workflow_summary
        event.workflow.summary
      end

      def execution_status
        graph_state = checkpoint_status
        return graph_state unless graph_state.nil? || graph_state == 'Not Started'

        event.workflow.human_status_name.titleize
      end

      # The raw checkpoint served by the `checkpoint` (deprecated 18.7) and
      # `compressedCheckpoint` fields. When the workflow reconstructs from blobs
      # its channel_values are no longer fully embedded in the header, so overlay
      # the reconstructed channels onto the header. Otherwise return the header
      # verbatim. Gated by read_checkpoints_from_blobs? like duoMessages.
      # A metadata-retention session serves only status and a content-free chat log,
      # except to its own run, which resumes from it.
      # Overrides the delegated Checkpoint#checkpoint attribute.
      delegator_override :checkpoint
      def checkpoint
        retained_checkpoint { event.workflow.reconstructed_channel_values(event) }
      end
      strong_memoize_attr :checkpoint

      # #checkpoint against blobs the page loader already fetched, sharing `decoded`
      # across the page so each blob is decoded once.
      def checkpoint_from(blobs_by_thread_ts, decoded)
        retained_checkpoint do
          event.workflow.reconstructed_channel_values_from(event, blobs_by_thread_ts, decoded: decoded)
        end
      end

      # LangGraph's checkpoint metadata can carry node output (`writes`).
      delegator_override :metadata
      def metadata
        return event.metadata unless reduce_content?

        ::Ai::DuoWorkflows::ContentRetention.checkpoint_metadata(event.metadata)
      end

      def reduce_content?
        workflow = event.workflow
        workflow.metadata_content_retention? && !workflow.session_service_account?(try(:current_user))
      end
      strong_memoize_attr :reduce_content?

      def duo_messages
        build_duo_messages(checkpoint_ui_chat_log)
      end

      # #duo_messages against blobs the page loader already fetched.
      def duo_messages_from(blobs_by_thread_ts)
        build_duo_messages(
          event.workflow.channel_message_history_from(event, 'ui_chat_log', blobs_by_thread_ts)
        )
      end

      # The most recent chat message only, for list previews -- reads the newest
      # ui_chat_log blob instead of folding the channel (Workflow#latest_channel_message).
      def last_duo_message
        last_duo_message_from(latest_ui_chat_log_delta)
      end

      # #last_duo_message from a ui_chat_log delta the page loader already decoded.
      def last_duo_message_from(delta)
        message = delta.last if delta.is_a?(Array)
        build_retained_duo_message(message) if message.is_a?(Hash)
      end

      def build_duo_messages(ui_chat_log)
        return [] unless ui_chat_log.is_a?(Array)

        ui_chat_log.filter_map { |message| build_retained_duo_message(message) if message.is_a?(Hash) }
      end

      def build_retained_duo_message(message)
        message = ::Ai::DuoWorkflows::ContentRetention.message(message) if reduce_content?
        self.class.build_duo_message(message)
      end

      # Only the latest checkpoint, the one the chat panel reads: one entry per
      # workflow, which reading an older checkpoint would otherwise replace.
      def cache_chat_history?
        thread_ts == event.workflow.latest_checkpoint_header&.thread_ts
      end

      private

      # The header, with the channel_values the block rebuilds overlaid when the
      # workflow reads from blobs, reduced for a metadata-retention session.
      def retained_checkpoint
        raw = event.checkpoint
        raw = raw.merge('channel_values' => yield) if raw && read_checkpoints_from_blobs?

        reduce_content? ? ::Ai::DuoWorkflows::ContentRetention.checkpoint(raw) : raw
      end

      def read_checkpoints_from_blobs?
        event.workflow.incremental_blob_gate.read?
      end

      # ui_chat_log only: on the blob path, the full message history across every
      # compaction group; on the header path, the current checkpoint's embedded
      # array (post-compaction only -- the header cannot span groups). Scoping to
      # one channel avoids decoding the other (often much larger) channels.
      def checkpoint_ui_chat_log
        return event.workflow.channel_message_history(event, 'ui_chat_log') if read_checkpoints_from_blobs?

        event.checkpoint&.dig('channel_values', 'ui_chat_log')
      end

      # status channel only: unlike ui_chat_log, status is a scalar (replace)
      # channel, so Workflow#reconstructed_channel folds its blobs to the latest
      # value and falls back to the header when the workflow wrote no status blobs.
      # Gated by read_checkpoints_from_blobs? like the message channels
      # above; execution_status keeps the nil/'Not Started' fallback to the
      # workflow's own status either way.
      def checkpoint_status
        return event.workflow.reconstructed_channel(event, 'status') if read_checkpoints_from_blobs?

        event.checkpoint&.dig('channel_values', 'status')
      end

      # Newest ui_chat_log entry only: the tail of the latest conversation blob on
      # the blob path, or the tail of the embedded array on the header path.
      def latest_ui_chat_log_delta
        if read_checkpoints_from_blobs?
          event.workflow.latest_channel_message(event, 'ui_chat_log')
        else
          event.checkpoint&.dig('channel_values', 'ui_chat_log')
        end
      end
    end
  end
end
