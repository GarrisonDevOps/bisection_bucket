# frozen_string_literal: true

module Gitlab
  module DuoWorkflow
    # Caches the ui_chat_log history of each workflow's latest checkpoint, so a read folds
    # only the blobs written since. An entry holds while each checkpoint it covers keeps its
    # blob count: a retry can add a blob to an old checkpoint.
    class ChatHistoryCache
      include ::Gitlab::Utils::StrongMemoize

      CHANNEL = 'ui_chat_log'
      # Bump when an entry's shape or ChannelValuesReconstructor#channel_history's output changes.
      VERSION = 2
      EXPIRES_IN = 1.hour

      # blob_counts and pending_counts map thread_ts to [blobs, versions] (see
      # Workflow#chat_log_blob_counts): the whole chain, and the part to fold onto `history`.
      # max_blob_id is the highest id `history` was folded from.
      ResumePoint = Data.define(:blob_counts, :history, :max_blob_id, :pending_counts)

      # Two copies of one workflow on a page can each see a different latest checkpoint,
      # so only the newest is cached.
      #
      # @param checkpoints [Array<Ai::DuoWorkflows::WorkflowCheckpointEventPresenter>] latest checkpoints
      def initialize(checkpoints)
        @checkpoints = checkpoints.group_by(&:workflow_id).transform_values { |list| list.max_by(&:thread_ts) }
        @writes = {}
      end

      # Whether #history serves the checkpoint. The others fold their chain uncached.
      #
      # @return [Boolean]
      def covers?(checkpoint)
        checkpoints[checkpoint.workflow_id]&.thread_ts == checkpoint.thread_ts
      end

      # @return [Array<String>] thread_ts of the checkpoints that no cached history covers
      def thread_ts_to_load
        checkpoints.each_value.flat_map { |checkpoint| resume_point(checkpoint).pending_counts.keys }.uniq
      end

      # Memoized per workflow: the fold appends to the cached history in place.
      #
      # @param checkpoint [Ai::DuoWorkflows::WorkflowCheckpointEventPresenter]
      # @param blobs [Array<Ai::DuoWorkflows::CheckpointBlob>] the workflow's blobs on #thread_ts_to_load
      # @return [Array, nil] the full chat history of the checkpoint
      def history(checkpoint, blobs)
        strong_memoize_with(:history, checkpoint.workflow_id) { fold(checkpoint, blobs) }
      end

      # Stores every history that #history folded new blobs into.
      #
      # @return [void]
      def write
        Rails.cache.write_multi(@writes, expires_in: EXPIRES_IN) if @writes.any?
        nil
      end

      private

      attr_reader :checkpoints

      def fold(checkpoint, blobs)
        resume = resume_point(checkpoint)
        pending = pending_blobs(resume, blobs)

        # A blob that committed after one with a higher id sorts into the cached part of the fold.
        if resume.history && pending.any? { |blob| blob[:id] < resume.max_blob_id }
          resume = full_fold(resume.blob_counts)
          reloaded = checkpoint.workflow
            .history_blobs_for(resume.blob_counts.keys, CHANNEL, skip_replaced_snapshots: true)
          pending = pending_blobs(resume, reloaded)
        end

        history = checkpoint.workflow.channel_message_history_from(
          checkpoint, CHANNEL, pending.group_by(&:thread_ts), from: resume.history
        )
        store(checkpoint, resume, pending, history)
        history
      end

      # The page may also have loaded blobs of the cached checkpoints, for an older checkpoint.
      def pending_blobs(resume, blobs)
        blobs.select { |blob| resume.pending_counts.key?(blob.thread_ts) }
      end

      # A blob the load missed (a lagging replica, or a delete) would stay out of every later read.
      # The load returns one blob per checkpoint and version.
      def store(checkpoint, resume, pending, history)
        return if pending.empty? || pending.size != resume.pending_counts.each_value.sum { |_blobs, versions| versions }

        @writes[cache_key(checkpoint.workflow_id)] = {
          blob_counts: resume.blob_counts,
          max_blob_id: pending.max_by { |blob| blob[:id] }[:id],
          history: history
        }
      end

      # How much of the checkpoint's chain the cached history covers: all of it, all but the
      # newer checkpoints, or nothing. A changed count means a retry or a fork.
      def resume_point(checkpoint)
        strong_memoize_with(:resume_point, checkpoint.workflow_id) do
          workflow = checkpoint.workflow
          counts = workflow.chat_log_blob_counts.slice(*workflow.full_ancestor_thread_ts(checkpoint))
          entry = cached_entries[cache_key(checkpoint.workflow_id)]
          next full_fold(counts) unless entry && entry[:blob_counts].all? { |ts, count| counts[ts] == count }

          ResumePoint.new(
            blob_counts: counts,
            history: entry[:history],
            max_blob_id: entry[:max_blob_id],
            pending_counts: counts.except(*entry[:blob_counts].keys)
          )
        end
      end

      def full_fold(counts)
        ResumePoint.new(blob_counts: counts, history: nil, max_blob_id: nil, pending_counts: counts)
      end

      def cached_entries
        Rails.cache.read_multi(*checkpoints.each_key.map { |workflow_id| cache_key(workflow_id) })
      end
      strong_memoize_attr :cached_entries

      def cache_key(workflow_id)
        ['duo_workflows', 'chat_history', VERSION, workflow_id]
      end
    end
  end
end
