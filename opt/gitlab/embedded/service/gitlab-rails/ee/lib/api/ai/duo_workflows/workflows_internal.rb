# frozen_string_literal: true

module API
  module Ai
    module DuoWorkflows
      # This API is intended to be consumed by a running Duo Workflow using
      # the ai_workflows scope token. These are requests coming from Duo Workflow
      # Service and Duo Workflow Executor. We should not add any more requests to
      # this API than needed by those 2 components. Otherwise add to
      # `API::Ai::DuoWorkflows::Workflows`.
      class WorkflowsInternal < ::API::Base
        include PaginationParams
        include APIGuard

        COMPRESS_LEVEL = 6 # Fast and good zlib compression

        helpers ::API::Helpers::DuoWorkflowHelpers

        allow_access_with_scope :ai_workflows

        feature_category :duo_agent_platform
        urgency :low

        before { authenticate! }

        helpers do
          def find_workflow!(id)
            workflow = ::Ai::DuoWorkflows::Workflow.for_user_with_id!(human_user.id, id)
            return workflow if Ability.allowed?(current_user, :read_duo_workflow, workflow)

            forbidden!
          end

          # A blocked flow (see FoundationalFlow#blocked_for?) also stops running sessions:
          # their checkpoint saves are refused, but status updates still work.
          def forbid_blocked_flow!(workflow)
            flow = workflow.foundational_flow
            return unless flow

            root = workflow.resource_parent.root_ancestor
            forbidden!('This flow is not available') if flow.blocked_for?(root)
          end

          def human_user
            current_user
          end

          def find_event!(workflow, id)
            workflow.events.find(id)
          end

          def render_response(response)
            if response.success?
              status :ok
              response.payload
            else
              status_code = error_status_for(response.reason)
              render_api_error!(response.message, status_code)
            end
          end

          def error_status_for(reason)
            {
              not_found: :not_found,
              unauthorized: :unauthorized,
              invalid_token_ownership: :forbidden,
              insufficient_token_scope: :forbidden,
              failed_to_revoke: :unprocessable_entity,
              missing_catalog_item_version: :unprocessable_entity,
              root_item_not_readable: :not_found
            }.fetch(reason, :bad_request)
          end

          def compress_checkpoint(checkpoint_data)
            Base64.strict_encode64(Zlib::Deflate.deflate(checkpoint_data.to_json, COMPRESS_LEVEL))
          end

          def uncompress_checkpoint(compressed_data)
            ::Gitlab::Json.parse(Zlib::Inflate.inflate(Base64.strict_decode64(compressed_data)))
          rescue ArgumentError, Zlib::Error, JSON::ParserError => e
            bad_request!("Invalid compressed checkpoint data: #{e.message}")
          end

          # Rebuilds channel_values for a page of slim headers and batch-loads their checkpoint_writes
          # (BulkInsertSafe forbids the association). With `compress`, only compressed_checkpoint is set
          # and each header stays slim, so the page holds one full checkpoint at a time.
          def reconstruct_page!(workflow, headers, channels:, compress:)
            return if headers.empty?

            writes_by_thread_ts = ::Ai::DuoWorkflows::CheckpointWrite
              .for_workflows_and_threads([workflow.id], headers.map(&:thread_ts))
              .group_by(&:thread_ts)
            blobs_by_thread_ts = workflow.blobs_by_thread_ts_for(headers, channels: channels)
            decoded = {}

            headers.each do |header|
              header.checkpoint_writes_preload = writes_by_thread_ts[header.thread_ts] || []
              values = workflow.reconstructed_channel_values_from(
                header, blobs_by_thread_ts, channels: channels, decoded: decoded
              )
              checkpoint = retained_checkpoint(workflow, header.checkpoint.merge('channel_values' => values))

              if compress
                header.compressed_checkpoint = compress_checkpoint(checkpoint)
              else
                header.checkpoint = checkpoint
              end
            end
          end

          # A metadata-retention session stores complete checkpoints so it can resume.
          # Only the session's own run reads them back: Rails mints its ai_workflows token for
          # the workflow's service account, acting for the user through composite identity.
          # The owner can mint an ai_workflows token for themselves (direct_access), so the
          # scope alone does not identify the run. Any other caller is served status and a
          # content-free chat log.
          def serve_reduced_content?(workflow)
            workflow.metadata_content_retention? && !workflow_service_account_token?(workflow)
          end

          # The composite identity check comes first: it holds only for a request that
          # authenticated with a token, so the scope check always has one.
          def workflow_service_account_token?(workflow)
            workflow.session_service_account?(current_user) && ai_workflows_token?
          end

          def ai_workflows_token?
            access_token.scopes.map(&:to_sym).include?(::Gitlab::Auth::AI_WORKFLOW)
          end

          def retained_checkpoint(workflow, data)
            return data unless serve_reduced_content?(workflow)

            ::Ai::DuoWorkflows::ContentRetention.checkpoint(data)
          end

          def retain_content!(workflow, checkpoints)
            return unless serve_reduced_content?(workflow)

            checkpoints.each do |checkpoint|
              checkpoint.checkpoint = ::Ai::DuoWorkflows::ContentRetention.checkpoint(checkpoint.checkpoint)
              checkpoint.metadata = ::Ai::DuoWorkflows::ContentRetention.checkpoint_metadata(checkpoint.metadata)
              serve_no_checkpoint_writes!(checkpoint)
            end
          end

          # Pending writes hold the prompt an interrupt pauses on; serve none, as GraphQL does.
          # In memory only: neither record is saved.
          def serve_no_checkpoint_writes!(checkpoint)
            if checkpoint.is_a?(::Ai::DuoWorkflows::CheckpointHeader)
              checkpoint.checkpoint_writes_preload = []
            else
              checkpoint.association(:checkpoint_writes).target = []
            end
          end

          def slice_channel_values!(checkpoints, channels)
            checkpoints.each do |checkpoint|
              data = checkpoint.checkpoint
              next unless data.is_a?(Hash) && data['channel_values'].is_a?(Hash)

              checkpoint.checkpoint = data.merge('channel_values' => data['channel_values'].slice(*channels))
            end
          end

          # A header without channel_keys records no live channels, so the fold cannot tell
          # a deleted channel from a live one (https://gitlab.com/gitlab-org/gitlab/-/issues/613975):
          # serve its legacy row, and let the caller 404 rather than fold a stale channel set.
          def checkpoint_to_serve(workflow, header)
            return workflow.checkpoints.latest_for_header(header) if header.channel_keys.nil?

            # The slim header omits channel_values; rebuild them from blobs so the
            # gateway receives a complete checkpoint.
            header.checkpoint = header.checkpoint.merge(
              'channel_values' => workflow.reconstructed_channel_values(header)
            )
            header
          end
        end

        namespace :ai do
          namespace :duo_workflows do
            desc 'Revoke ai_workflows token' do
              detail 'Revokes an active Duo Workflows authentication token.'
              tags %w[gitlab_duo_workflows internal_operations]
              success code: 200
              failure [
                { code: 400, message: 'Bad request' },
                { code: 401, message: 'Unauthorized' },
                { code: 403, message: 'Forbidden' },
                { code: 422, message: 'Unprocessable Entity' }
              ]
            end
            params do
              requires :token, type: String, desc: 'Access token to revoke.'
            end
            route_setting :authorization, skip_granular_token_authorization: :ai_workflows_oauth_auth
            post :revoke_token do
              service = ::Ai::DuoWorkflows::RevokeTokenService.new(
                token: params[:token],
                current_user: current_user
              )

              render_response(service.execute)
            end

            namespace :workflows do
              desc 'Get workflow details' do
                detail 'Retrieves detailed information about a specific workflow by its ID.'
                success code: 200, model: ::API::Entities::Ai::DuoWorkflows::Workflow
                failure [
                  { code: 400, message: 'Bad request' },
                  { code: 401, message: 'Unauthorized' },
                  { code: 403, message: 'Forbidden' },
                  { code: 404, message: 'Not found' }
                ]
                tags %w[gitlab_duo_workflows internal_operations]
              end
              params do
                requires :id, type: Integer, desc: 'ID of the workflow.'
              end
              namespace '/:id' do
                params do
                  requires :id, type: Integer, desc: 'ID of the workflow.', documentation: { example: 1 }
                end
                route_setting :authorization, skip_granular_token_authorization: :ai_workflows_oauth_auth
                get do
                  require_gitlab_workhorse!

                  workflow = find_workflow!(params[:id])
                  push_ai_gateway_headers(scope: workflow.resource_parent,
                    subject: workflow.service_account || current_user)

                  present workflow, with: ::API::Entities::Ai::DuoWorkflows::Workflow
                end

                desc 'Get the AI Catalog item a workflow runs, with its sub-items' do
                  detail 'Returns the saved AI Catalog item this session runs and its resolved subagents. ' \
                    'A subagent the user cannot use has an error instead of a definition. ' \
                    'When a setting turns subagents off, sub_items is empty and ' \
                    'sub_items_skipped_reason says which setting.'
                  tags %w[gitlab_duo_workflows internal_operations]
                  success code: 200
                  failure [
                    { code: 404, message: 'The flow was not found or the user cannot read it' },
                    { code: 422, message: 'Workflow does not run a saved AI Catalog item' }
                  ]
                end
                params do
                  requires :id, type: Integer, desc: 'The ID of the workflow', documentation: { example: 1 }
                end
                route_setting :authorization, skip_granular_token_authorization: :ai_workflows_oauth_auth
                get :catalog_items do
                  require_gitlab_workhorse!

                  workflow = find_workflow!(params[:id])
                  response = ::Ai::Catalog::ResolveWorkflowItemsService.new(
                    workflow: workflow,
                    current_user: current_user
                  ).execute

                  render_response(response)
                end

                desc 'Update the workflow status' do
                  detail 'Updates the execution status of a specified workflow.'
                  tags %w[gitlab_duo_workflows internal_operations]
                  success code: 200
                  failure [
                    { code: 400, message: 'Bad request' },
                    { code: 401, message: 'Unauthorized' },
                    { code: 403, message: 'Forbidden' },
                    { code: 404, message: 'Not found' }
                  ]
                end
                params do
                  requires :id, type: Integer, desc: 'ID of the workflow.', documentation: { example: 1 }
                  requires :status_event, type: String, desc: 'Status event to apply to the workflow, for example ' \
                                                          '`finish`.',
                    documentation: { example: 'finish' }
                  optional :drop_reason, type: String, limit: 64,
                    desc: 'Why the service dropped the session. Ignored unless status_event is drop; ' \
                      'a value the service may not name is recorded as api_reported',
                    documentation: { example: 'token_rejected' }
                end
                route_setting :authorization, skip_granular_token_authorization: :ai_workflows_oauth_auth
                patch do
                  workflow = find_workflow!(params[:id])
                  forbidden! unless Ability.allowed?(current_user, :update_duo_workflow, workflow)

                  # Coerced rather than rejected: the service only logs a failed status
                  # update, so a 400 here would lose the drop itself, not just the reason.
                  if params[:status_event] == 'drop'
                    service_reasons = ::Ai::DuoWorkflows::Workflow::SERVICE_DROP_REASONS
                    drop_reason = service_reasons.include?(params[:drop_reason]) ? params[:drop_reason] : 'api_reported'
                  end

                  service = ::Ai::DuoWorkflows::UpdateWorkflowStatusService.new(
                    workflow: workflow,
                    status_event: params[:status_event],
                    current_user: current_user,
                    drop_reason: drop_reason
                  )

                  render_response(service.execute)
                end

                namespace :checkpoints do
                  before do
                    require_gitlab_workhorse!
                  end
                  desc 'Create workflow checkpoint' do
                    detail 'Creates a new checkpoint state for an active workflow execution.'
                    success code: 201, model: ::API::Entities::Ai::DuoWorkflows::BasicCheckpoint
                    failure [
                      { code: 400, message: 'Bad request' },
                      { code: 401, message: 'Unauthorized' },
                      { code: 403, message: 'Forbidden' },
                      { code: 404, message: 'Not found' }
                    ]
                    tags %w[gitlab_duo_workflows internal_operations]
                  end
                  params do
                    requires :id, type: Integer, desc: 'ID of the workflow.'
                    requires :thread_ts, type: String, desc: 'LangGraph `thread_ts` of the checkpoint.'
                    optional :parent_ts, type: String, desc: 'The parent ts'
                    optional :checkpoint_ns, type: String, limit: 4096,
                      desc: "LangGraph checkpoint namespace this checkpoint belongs to. Omitted (or blank) for the " \
                        "flow's own top-level checkpoint lineage. Set to LangGraph's namespace string for one nested " \
                        "subgraph invocation, for example a delegated subagent dispatched by `DelegationNode`."
                    optional :checkpoint, type: Hash, desc: "Checkpoint content"
                    optional :compressed_checkpoint, type: String,
                      desc: "Checkpoint content zlib compressed and base64 encoded"
                    requires :metadata, type: Hash, desc: 'Checkpoint metadata.'
                    optional :model_metadata_json, type: String, desc: 'JSON string of the model metadata.'
                    optional :flow_metadata_json, type: String, desc: 'JSON string of the flow metadata.'
                    optional :current_thread, type: Integer, default: 0,
                      desc: 'Hint used to group blobs by thread during checkpoint reconstruction.'
                    # Only incremental-only mode sends this; other modes send the
                    # channel_values it is otherwise derived from. The identity coercion stops
                    # dry-types turning a blank scalar into [], stored as "no live channels".
                    optional :channel_keys, type: Array[String],
                      limit: ::Ai::DuoWorkflows::CheckpointHeader::CHANNEL_KEYS_LIMIT,
                      coerce_with: ->(val) { val },
                      regexp: { value: /\A.{1,255}\z/m, message: 'items must be 1 to 255 characters' },
                      desc: 'Live channel membership of the checkpoint.'
                    optional :channel_blobs, type: Array, limit: 100,
                      desc: 'Per-channel blobs for incremental checkpoint storage.' do
                      requires :channel, type: String, limit: 255, desc: 'Name of the channel.'
                      requires :version, type: String, limit: 255, desc: 'Version of the channel.'
                      requires :write_type, type: String, limit: 255,
                        desc: 'Blob serialization type. The read path decodes zlib-compressed JSON, ' \
                          'so producers must send "json".'
                      requires :step_action, type: String, values: %w[conversation compaction],
                        desc: 'Whether the blob is appended to the stored channel data (`conversation`) or replaces ' \
                          'it (`compaction`).'
                      # base64 of the 1 MiB raw BLOB_DATA_LIMIT is 4 * ceil(1_048_576 / 3) = 1_398_104 chars;
                      # bounding here rejects oversized payloads before Base64.strict_decode64 allocates them.
                      requires :data, type: String, limit: 1_398_104, desc: 'Base64-encoded blob bytes.'
                    end
                  end
                  route_setting :authorization, skip_granular_token_authorization: :ai_workflows_oauth_auth
                  post do
                    workflow = find_workflow!(params[:id])
                    forbid_blocked_flow!(workflow)

                    checkpoint = if params[:checkpoint].present?
                                   params[:checkpoint]
                                 elsif params[:compressed_checkpoint].present?
                                   uncompress_checkpoint(params[:compressed_checkpoint])
                                 end

                    bad_request!('Either checkpoint or compressed_checkpoint must be provided') unless checkpoint

                    checkpoint_params = declared_params(include_missing: false)
                                          .except(:id)
                                          .merge(checkpoint: checkpoint)

                    service = ::Ai::DuoWorkflows::CreateCheckpointService.new(
                      workflow: workflow, params: checkpoint_params)
                    result = service.execute

                    bad_request!(result[:message]) if result[:status] == :error

                    present result[:checkpoint], with: ::API::Entities::Ai::DuoWorkflows::BasicCheckpoint
                  end

                  desc 'List all workflow checkpoints' do
                    detail 'Lists all checkpoints associated with a specific workflow.'
                    success code: 200, model: ::API::Entities::Ai::DuoWorkflows::Checkpoint, is_array: true
                    failure [
                      { code: 400, message: 'Bad request' },
                      { code: 401, message: 'Unauthorized' },
                      { code: 403, message: 'Forbidden' },
                      { code: 404, message: 'Not found' }
                    ]
                    tags %w[gitlab_duo_workflows internal_operations]
                  end
                  params do
                    optional :accept_compressed, type: Boolean, default: false, desc: 'If `true`, returns compressed ' \
                                                                                  'checkpoints.'
                    optional :checkpoint_ns, type: String, limit: 4096,
                      desc: 'Only return checkpoints belonging to this LangGraph checkpoint namespace ' \
                        '(the flow\'s own top-level lineage if omitted or blank). Unset (the default): ' \
                        'return checkpoints from every lineage, unfiltered, preserving prior behavior.'
                    optional :channels, type: Array[String],
                      limit: ::Ai::DuoWorkflows::CheckpointHeader::CHANNEL_KEYS_LIMIT,
                      allow_blank: false,
                      coerce_with: ::API::Validations::Types::CommaSeparatedToArray.coerce,
                      regexp: { value: /\A.{1,255}\z/m, message: 'items must be 1 to 255 characters' },
                      desc: 'Comma-separated channels to return in each checkpoint\'s channel_values, ' \
                        'at most 100, each 1 to 255 characters. Omit to return every channel.'
                  end
                  route_setting :authorization, skip_granular_token_authorization: :ai_workflows_oauth_auth
                  get do
                    workflow = find_workflow!(params[:id])

                    # An incremental workflow writes a header for every checkpoint,
                    # so headers are a superset of `checkpoints` here: read them
                    # alone rather than merging. Blobs also carry the pre-compaction
                    # history the full row truncates.
                    reconstruct = workflow.incremental_blob_gate.read?
                    # rubocop:disable Gitlab/Ai/AvoidDirectCheckpointTableRead -- legacy branch of the reconstruct gate
                    checkpoints = if reconstruct
                                    workflow.checkpoint_headers.in_reverse_checkpoint_order
                                  else
                                    workflow.checkpoints.ordered_with_writes
                                  end
                    # rubocop:enable Gitlab/Ai/AvoidDirectCheckpointTableRead

                    checkpoints = checkpoints.for_checkpoint_ns(params[:checkpoint_ns]) if params.key?(:checkpoint_ns)

                    checkpoints = paginate(checkpoints)

                    if reconstruct
                      reconstruct_page!(workflow, checkpoints,
                        channels: params[:channels], compress: params[:accept_compressed])
                      # After reconstruct_page!, which loads the writes; it reduces the channels it folds itself.
                      retain_content!(workflow, checkpoints)
                    else
                      retain_content!(workflow, checkpoints)
                      slice_channel_values!(checkpoints, params[:channels]) if params[:channels]

                      if params[:accept_compressed]
                        checkpoints.each { |cp| cp.compressed_checkpoint = compress_checkpoint(cp.checkpoint) }
                      end
                    end

                    present checkpoints, with: ::API::Entities::Ai::DuoWorkflows::Checkpoint
                  end

                  # Reconstructs a checkpoint from the slim header + incremental
                  # blobs, keyed by the langgraph thread_ts, without reading the full
                  # p_duo_workflows_checkpoints row (which is being retired). thread_ts
                  # is the durable identifier the gateway already holds; the numeric
                  # checkpoint id is tied to the full-checkpoint table.
                  desc 'Get a workflow checkpoint reconstructed from incremental blobs' do
                    detail 'Retrieves a full workflow checkpoint reconstructed from incremental data blobs.'
                    success code: 200, model: ::API::Entities::Ai::DuoWorkflows::Checkpoint
                    failure [
                      { code: 400, message: 'Bad request' },
                      { code: 401, message: 'Unauthorized' },
                      { code: 403, message: 'Forbidden' },
                      { code: 404, message: 'Not found' }
                    ]
                    tags %w[gitlab_duo_workflows internal_operations]
                  end
                  params do
                    requires :thread_ts, type: String, desc: 'The langgraph thread_ts of the checkpoint'
                    optional :accept_compressed, type: Boolean, default: false, desc: 'If `true`, returns the ' \
                                                                                  'compressed checkpoint.'
                  end
                  route_setting :authorization, skip_granular_token_authorization: :ai_workflows_oauth_auth
                  get 'by_thread_ts' do
                    workflow = find_workflow!(params[:id])

                    # The gateway owns the read decision and calls this only when incremental_checkpoints_enabled
                    # is true, so serve whenever a header exists. A workflow without blobs has no header and 404s.
                    header = workflow.checkpoint_header_for(params[:thread_ts])
                    not_found! unless header

                    # Resolved before compression so the compressed payload carries the
                    # channel_values too.
                    checkpoint = checkpoint_to_serve(workflow, header)
                    not_found! unless checkpoint
                    retain_content!(workflow, [checkpoint])

                    if params[:accept_compressed]
                      checkpoint.compressed_checkpoint = compress_checkpoint(checkpoint.checkpoint)
                    end

                    present checkpoint, with: ::API::Entities::Ai::DuoWorkflows::Checkpoint
                  end

                  params do
                    requires :checkpoint_id, type: Integer, desc: 'ID of the checkpoint.'
                  end
                  namespace '/:checkpoint_id' do
                    desc 'Get details on a workflow checkpoint' do
                      detail 'Retrieves detailed information about a specific workflow checkpoint.'
                      success code: 200, model: ::API::Entities::Ai::DuoWorkflows::Checkpoint
                      failure [
                        { code: 400, message: 'Bad request' },
                        { code: 401, message: 'Unauthorized' },
                        { code: 403, message: 'Forbidden' },
                        { code: 404, message: 'Not found' }
                      ]
                      tags %w[gitlab_duo_workflows internal_operations]
                    end
                    params do
                      requires :checkpoint_id, type: Integer, desc: 'ID of the checkpoint.',
                        documentation: { example: 1 }
                      optional :accept_compressed, type: Boolean, default: false, desc: 'If `true`, returns the ' \
                                                                                    'compressed checkpoint.'
                    end
                    route_setting :authorization, skip_granular_token_authorization: :ai_workflows_oauth_auth
                    get do
                      workflow = find_workflow!(params[:id])
                      # rubocop:disable Gitlab/Ai/AvoidDirectCheckpointTableRead -- legacy-only route (a header has no numeric checkpoint id; use by_thread_ts), removed in https://gitlab.com/gitlab-org/gitlab/-/work_items/611971
                      checkpoint = workflow.checkpoints.with_checkpoint_writes.find_by_id(params[:checkpoint_id])
                      # rubocop:enable Gitlab/Ai/AvoidDirectCheckpointTableRead

                      not_found! unless checkpoint
                      retain_content!(workflow, [checkpoint])

                      if params[:accept_compressed]
                        checkpoint.compressed_checkpoint = compress_checkpoint(checkpoint.checkpoint)
                      end

                      present checkpoint, with: ::API::Entities::Ai::DuoWorkflows::Checkpoint
                    end
                  end
                end

                namespace :checkpoint_writes_batch do
                  before do
                    require_gitlab_workhorse!
                  end

                  desc 'Create multiple workflow checkpoint writes' do
                    detail 'Writes multiple checkpoint entries for a workflow in a single request.'
                    success code: 200
                    failure [
                      { code: 400, message: 'Bad request' },
                      { code: 401, message: 'Unauthorized' },
                      { code: 403, message: 'Forbidden' },
                      { code: 404, message: 'Not found' }
                    ]
                    tags %w[gitlab_duo_workflows internal_operations]
                  end
                  params do
                    requires :id, type: Integer, desc: 'ID of the workflow.'
                    requires :thread_ts, type: String, desc: 'LangGraph `thread_ts` of the checkpoint.'
                    requires :checkpoint_writes, type: Array, allow_blank: false, desc: 'List of checkpoint writes.' do
                      requires :task, type: String, desc: 'ID of the task.'
                      requires :idx, type: Integer, desc: 'Index of the checkpoint write.'
                      requires :channel, type: String, desc: 'Name of the channel.'
                      requires :write_type, type: String, desc: 'Type of data.'
                      requires :data, type: String, desc: 'Checkpoint write data.'
                    end
                  end
                  route_setting :authorization, skip_granular_token_authorization: :ai_workflows_oauth_auth
                  post do
                    workflow = find_workflow!(params[:id])
                    result = ::Ai::DuoWorkflows::CreateCheckpointWriteBatchService.new(
                      workflow: workflow,
                      params: declared_params(include_missing: false).except(:id)
                    ).execute

                    bad_request!(result.message) if result.error?

                    status :ok
                  end
                end

                namespace :events do
                  desc 'Create workflow event' do
                    detail 'Creates a new event for a specified workflow execution.'
                    success code: 201, model: ::API::Entities::Ai::DuoWorkflows::Event
                    failure [
                      { code: 400, message: 'Bad request' },
                      { code: 401, message: 'Unauthorized' },
                      { code: 403, message: 'Forbidden' },
                      { code: 404, message: 'Not found' }
                    ]
                    tags %w[gitlab_duo_workflows internal_operations]
                  end
                  params do
                    requires :id, type: Integer, desc: 'ID of the workflow.'
                    requires :event_type, type: String, values: ::Ai::DuoWorkflows::Event.event_types.keys,
                      desc: 'Type of event.'
                    requires :message, type: String, desc: 'Message from the human.'
                    optional :correlation_id, type: String, desc: 'Correlation ID for tracking events.',
                      regexp: ::Ai::DuoWorkflows::Event::UUID_REGEXP
                  end
                  route_setting :authorization, skip_granular_token_authorization: :ai_workflows_oauth_auth
                  post do
                    workflow = find_workflow!(params[:id])
                    event_params = declared_params(include_missing: false).except(:id)
                    service = ::Ai::DuoWorkflows::CreateEventService.new(
                      workflow: workflow,
                      params: event_params.merge(event_status: :queued)
                    )
                    result = service.execute

                    bad_request!(result[:message]) if result[:status] == :error

                    present result[:event], with: ::API::Entities::Ai::DuoWorkflows::Event
                  end

                  desc 'List all workflow events' do
                    detail 'Retrieves a list of all events associated with a specific workflow.'
                    success code: 200, model: ::API::Entities::Ai::DuoWorkflows::Event, is_array: true
                    failure [
                      { code: 400, message: 'Bad request' },
                      { code: 401, message: 'Unauthorized' },
                      { code: 403, message: 'Forbidden' },
                      { code: 404, message: 'Not found' }
                    ]
                    tags %w[gitlab_duo_workflows internal_operations]
                  end
                  route_setting :authorization, skip_granular_token_authorization: :ai_workflows_oauth_auth
                  get do
                    workflow = find_workflow!(params[:id])
                    events = workflow.events.queued
                    present paginate(events), with: ::API::Entities::Ai::DuoWorkflows::Event
                  end

                  desc 'Update workflow event' do
                    detail 'Updates an existing event for a specified workflow.'
                    success code: 200, model: ::API::Entities::Ai::DuoWorkflows::Event
                    failure [
                      { code: 400, message: 'Bad request' },
                      { code: 401, message: 'Unauthorized' },
                      { code: 403, message: 'Forbidden' },
                      { code: 404, message: 'Not found' }
                    ]
                    tags %w[gitlab_duo_workflows internal_operations]
                  end
                  params do
                    requires :id, type: Integer, desc: 'ID of the workflow.'
                    requires :event_id, type: Integer, desc: 'ID of the event.'
                    requires :event_status, type: String, values: %w[queued delivered], desc: 'Status of the event.'
                  end
                  route_setting :authorization, skip_granular_token_authorization: :ai_workflows_oauth_auth
                  put '/:event_id' do
                    workflow = find_workflow!(params[:id])
                    event = find_event!(workflow, params[:event_id])
                    event_params = declared_params(include_missing: false).except(:id, :event_id)
                    service = ::Ai::DuoWorkflows::UpdateEventService.new(
                      event: event,
                      params: event_params
                    )
                    result = service.execute

                    bad_request!(result[:message]) if result[:status] == :error

                    present result[:event], with: ::API::Entities::Ai::DuoWorkflows::Event
                  end
                end
              end
            end
          end
        end
      end
    end
  end
end
