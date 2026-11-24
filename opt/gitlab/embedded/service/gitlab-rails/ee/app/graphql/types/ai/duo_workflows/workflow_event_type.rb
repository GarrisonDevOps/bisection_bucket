# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      class WorkflowEventType < Types::BaseObject
        graphql_name 'DuoWorkflowEvent'
        description "Events that describe the history and progress of a GitLab Duo Agent Platform session"
        present_using ::Ai::DuoWorkflows::WorkflowCheckpointEventPresenter
        authorize :read_duo_workflow_event
        authorize_granular_token permissions: :read_duo_workflow, boundary: :user, boundary_type: :user

        COMPRESS_LEVEL = 6 # Fast and good zlib compression
        DUO_MESSAGES_CAP = 100

        def self.authorization_scopes
          [:api, :read_api, :ai_features, :ai_workflows]
        end

        field :checkpoint, Types::JsonStringType,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          deprecated: { reason: 'Checkpoints are big & contain internal langgraph details', milestone: '18.7' },
          description: 'Checkpoint of the event.'

        field :compressed_checkpoint, GraphQL::Types::String,
          null: true,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          description: 'Checkpoint of the event, zlib-compressed and Base64-encoded.'

        field :metadata, Types::JsonStringType,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          description: 'Metadata associated with the event.'

        field :workflow_status, Types::Ai::DuoWorkflows::WorkflowStatusEnum,
          description: 'Status of the session.'

        field :execution_status, GraphQL::Types::String,
          null: false, description: "Granular status of the session's execution.",
          experiment: { milestone: '17.10' }

        field :errors, [GraphQL::Types::String],
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: true, description: 'Message errors.'

        field :thread_ts, GraphQL::Types::String,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          description: 'UUID v7 timestamp identifier for the conversation thread/session in LangGraph state management.'

        # rubocop:disable GraphQL/ExtractType -- no need to extract fields into a separate field
        field :parent_ts, GraphQL::Types::String,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          description: 'UUID v7 timestamp identifier of the parent message for branched conversations or responses.'

        field :checkpoint_ns, GraphQL::Types::String,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          experiment: { milestone: '19.3' },
          description: 'LangGraph checkpoint namespace this checkpoint belongs to. Blank for the ' \
            'session\'s own top-level checkpoint lineage; this field only ever surfaces that lineage ' \
            '(via first_checkpoint/latest_checkpoint), never a nested subgraph invocation\'s own.'

        field :current_thread, GraphQL::Types::Int,
          null: false,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          experiment: { milestone: '19.4' },
          description: 'Compaction group this checkpoint belongs to. The writer bumps it on every ' \
            'compaction and resets it when its process restarts, so a client that resumes a session ' \
            'must read it back from here to keep numbering the groups correctly.'

        field :workflow_goal, GraphQL::Types::String,
          description: 'Goal of the session.'

        field :workflow_definition, GraphQL::Types::String,
          description: 'GitLab Duo Agent Platform flow type based on its capabilities.'
        # rubocop:enable GraphQL/ExtractType -- we want to keep this way for backwards compatibility

        field :duo_messages, [Types::Ai::DuoWorkflows::DuoMessageType],
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          description: 'Messages from the ui_chat_log for the checkpoint. ' \
            "Returns only the newest #{DUO_MESSAGES_CAP} when the `duo_workflow_cap_duo_messages` " \
            "feature flag is enabled."
        field :messages, Types::Ai::DuoWorkflows::DuoMessageType.connection_type,
          null: true,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          description: 'Messages from the ui_chat_log for the checkpoint, oldest first. ' \
            'Pass `last` to read the newest messages, then `before` with `startCursor` to page ' \
            'back to older ones.'

        field :last_duo_message, Types::Ai::DuoWorkflows::DuoMessageType,
          null: true,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          experiment: { milestone: '19.3' },
          description: 'Most recent message from the ui_chat_log for the checkpoint. ' \
            'Cheaper than duoMessages for list previews: it reads only the latest message ' \
            'instead of the full chat log.'

        field :latest_todo_duo_message, Types::Ai::DuoWorkflows::DuoMessageType,
          null: true,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          experiment: { milestone: '19.6' },
          description: 'Most recent `todo_write` tool message with todos from the ui_chat_log for the ' \
            'checkpoint. Returns one message instead of the full chat log.'

        # rubocop:disable GraphQL/ExtractType -- no need to extract fields into a separate field
        field :checkpoint_writes, [Types::Ai::DuoWorkflows::CheckpointWriteType],
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          experiment: { milestone: '19.3' },
          description: 'Pending writes associated with the checkpoint, e.g. interrupts awaiting resumption.'
        # rubocop:enable GraphQL/ExtractType -- no need to extract fields into a separate field

        def checkpoint
          batched_checkpoint
        end

        def compressed_checkpoint
          Gitlab::Graphql::Lazy.with_value(batched_checkpoint) do |checkpoint|
            Base64.strict_encode64(Zlib::Deflate.deflate(checkpoint.to_json, COMPRESS_LEVEL)) if checkpoint
          end
        end

        def duo_messages
          cap = Feature.enabled?(:duo_workflow_cap_duo_messages, object.workflow.resource_parent.root_ancestor)

          chat_log(cap: cap)
        end

        def messages
          chat_log(cap: false)
        end

        # Reads the uncapped chat log, so a todo older than the duoMessages cap is still found.
        # It shares the fold with `messages`, and with duoMessages when the cap is off.
        #
        # @return [Gitlab::Graphql::Lazy] resolves to a DuoMessage, or nil
        def latest_todo_duo_message
          ::Gitlab::Graphql::Lazy.with_value(chat_log(cap: false)) do |messages|
            ::Ai::DuoWorkflows::WorkflowCheckpointEventPresenter.latest_todo_duo_message(messages)
          end
        end

        # `checkpoint_writes` isn't preloaded by the callers of this type (e.g. the
        # first_checkpoint/latest_checkpoint fields resolve one Checkpoint per workflow
        # independently), so a naive `object.checkpoint_writes` here would issue a
        # separate query per resolved checkpoint. Batch those into a single query across
        # every checkpoint requested in this GraphQL request.
        def checkpoint_writes
          # Pending writes hold the prompt an interrupt pauses on; metadata-retention sessions serve
          # none, except to their own run.
          return [] if object.reduce_content?

          BatchLoader::GraphQL.for([object.workflow_id, object.thread_ts]).batch(default_value: []) do |keys, loader|
            workflow_ids = keys.map(&:first).uniq
            thread_tss = keys.map(&:last).uniq

            ::Ai::DuoWorkflows::CheckpointWrite.for_workflows_and_threads(workflow_ids, thread_tss).find_each do |write|
              loader.call([write.workflow_id, write.thread_ts]) { |writes| writes << write }
            end
          end
        end

        # Resolves the newest chat message for this checkpoint, batched across the page.
        #
        # @return [BatchLoader::GraphQL] resolves to a DuoMessage, or nil
        def last_duo_message
          ::BatchLoader::GraphQL.for(object).batch do |presenters, loader|
            ::Ai::DuoWorkflows::WorkflowCheckpointEventPresenter
              .batch_last_duo_messages(presenters) { |presenter, message| loader.call(presenter, message) }
          end
        end

        private

        # Folding a chat log walks the checkpoint's ancestor chain, several
        # queries per row. Load the chain data for the whole page at once.
        def chat_log(cap:)
          ::BatchLoader::GraphQL.for(object).batch(key: cap) do |presenters, loader|
            ::Ai::DuoWorkflows::WorkflowCheckpointEventPresenter.batch_duo_messages(presenters) do |presenter, messages|
              loader.call(presenter, cap ? messages.last(DUO_MESSAGES_CAP) : messages)
            end
          end
        end

        # Rebuilding a checkpoint folds its whole blob chain, and chains on a page
        # overlap. Shared by both checkpoint fields, so selecting both rebuilds once.
        def batched_checkpoint
          ::BatchLoader::GraphQL.for(object).batch do |presenters, loader|
            ::Ai::DuoWorkflows::WorkflowCheckpointEventPresenter
              .batch_checkpoints(presenters) { |presenter, checkpoint| loader.call(presenter, checkpoint) }
          end
        end
      end
    end
  end
end
