# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Runs a workflow against Workhorse's server-side execution endpoint
    # (POST .../workflows/:id/execute), for callers that cannot execute the
    # actions the Duo Workflow Service (DWS) emits themselves -- such as a chat
    # turn arriving from Slack. Workhorse opens the DWS stream and answers those
    # actions instead of a CI job doing it.
    #
    # Blocks for the whole turn, so it is only safe to call from a background job.
    # A detached request blocks only until Workhorse has started the run, and
    # the turn then goes on without the caller.
    class ServerSideExecutionService
      EXECUTE_PATH = '/api/v4/ai/duo_workflows/workflows/%<id>s/execute'
      CLIENT_VERSION = '1.0'
      # Reaches DWS as x-gitlab-client-type, so these sessions are attributable
      # apart from the client-driven ones (`browser`, `vscode`, ...).
      CLIENT_TYPE = 'gitlab-server-side'
      FEATURE_SETTING_NAME_HEADER = 'X-Gitlab-Agent-Platform-Feature-Setting-Name'

      OPEN_TIMEOUT = 10.seconds
      # Per read, not per turn: Workhorse sends a keepalive every 20 seconds, so
      # this only trips when the connection is wedged. A turn may run far longer.
      READ_TIMEOUT = 5.minutes

      # A turn is over once the flow pauses for the user, goes idle, or finishes. Anything
      # else -- most importantly still running, meaning the stream drained
      # without DWS pausing -- is a failed turn.
      TURN_END_STATUS_GROUPS = %i[awaiting_input completed].freeze

      # The stream closing and DWS reporting the new status over the internal API
      # are not ordered relative to each other, so the first read can still say
      # running. Anything slower than this is a stuck workflow, not that race.
      STATUS_POLL_ATTEMPTS = 3
      STATUS_POLL_INTERVAL = 1.second

      # context: the turn's run context (ExecuteRunService::CONTEXT_KEYS).
      # detached: asks for a detached run. Rails pre-authorization decides
      # whether the request gets one, so the turn may still stream.
      def initialize(workflow:, goal:, approval: nil, context: {}, detached: false)
        @workflow = workflow
        @goal = goal
        @approval = approval
        @context = context
        @detached = detached
        @stream_started = false
      end

      # Yields once per action received, without arguments: DWS persists
      # checkpoints through the internal API as it goes, so a caller wanting to
      # render progress should re-read the workflow rather than read the stream.
      #
      # A turn Workhorse took on detached returns success with `detached: true`
      # in the payload, before the turn is over.
      def execute(&on_action)
        token_result = generate_oauth_token
        return token_result if token_result.error?

        request_outcome = call_execute_endpoint(token_result.payload[:token], &on_action)
        return request_outcome if request_outcome

        await_turn_end
      end

      private

      attr_reader :workflow, :goal, :approval, :context, :detached

      def generate_oauth_token
        result = context_service.generate_oauth_token
        return ServiceResponse.error(message: result.message, reason: :execute_workflow_failed) if result.error?

        ServiceResponse.success(payload: { token: result.payload[:oauth_access_token].plaintext_token })
      end

      # The bearer is the user's own token, the same way Web Agentic Chat's is. When the project
      # allows flow execution, pre-authorization mints the composite identity token of the
      # workflow's service account in its place. A tool call needing human approval pauses the
      # flow rather than being pre-approved here.
      def context_service
        ::Ai::DuoWorkflows::WorkflowContextGenerationService.new(
          current_user: workflow.user,
          organization: resource_parent.organization,
          workflow_definition: workflow.workflow_definition,
          surface: ::Ai::ToolRules::GovernanceSurface::WEB,
          workflow_id: workflow.id
        )
      end

      # Returns a response when the request alone decides the outcome, or nil to
      # let the workflow's status decide.
      def call_execute_endpoint(token, &on_action)
        response = Gitlab::HTTP.post(
          request_url,
          query: request_query,
          body: Gitlab::Json.dump(request_body),
          headers: {
            'Content-Type' => 'application/json',
            'Authorization' => "Bearer #{token}",
            FEATURE_SETTING_NAME_HEADER => feature_setting_name
          }.compact,
          # The URL is this instance's own, built from configuration and an ID.
          allow_local_requests: true,
          open_timeout: OPEN_TIMEOUT,
          read_timeout: READ_TIMEOUT,
          stream_body: true,
          &stream_handler(on_action)
        )

        return ServiceResponse.success(payload: { workflow: workflow, detached: true }) if response.code == 202
        return if response.success?

        # Workhorse commits the response header lazily, so a failure status means
        # the turn never started and the workflow's status would say nothing.
        ServiceResponse.error(
          message: "Server-side execution request failed with status #{response.code}",
          reason: reason_for_status(response.code)
        )
      rescue *Gitlab::HTTP::HTTP_ERRORS => e
        ::Gitlab::ErrorTracking.track_exception(e, workflow_id: workflow.id)
        # Losing the connection mid-turn says nothing about whether the turn
        # completed; the workflow's status does.
        return if @stream_started

        ServiceResponse.error(message: e.message, reason: :execute_workflow_failed)
      end

      # Gitlab::HTTP yields transport-level fragments, which say nothing about
      # where actions begin and end: one can carry several actions, part of one,
      # or a keepalive. Only whether the line being assembled has any content is
      # carried across fragments, so an action -- which can approach Workhorse's
      # 4 MB message limit, and whose content nothing here reads -- is never
      # assembled in full.
      def stream_handler(on_action)
        line_has_content = false

        ->(fragment) do
          # HTTParty runs this while reading the body, before it looks at the
          # status, so an error response would otherwise arrive as progress.
          next unless fragment.code == 200
          # "".split("\n", -1) is [] rather than [""], leaving no partial line.
          next if fragment.empty?

          @stream_started = true
          *completed_lines, partial_line = fragment.split("\n", -1)

          completed_lines.each do |line|
            # An empty line is a keepalive rather than an action.
            notify(on_action) if line_has_content || !line.empty?
            line_has_content = false
          end

          line_has_content ||= !partial_line.empty?
        end
      end

      # Progress is advisory: a caller failing to render it must neither abandon
      # the turn nor be reported as a transport failure by call_execute_endpoint.
      def notify(on_action)
        on_action&.call
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e, workflow_id: workflow.id)
      end

      # Pre-authorization selects the model and self-hosted billing by this name, as it does
      # for a CI run. A flow with only the default feature keeps the agentic chat fallback
      # there, as Slack's flow does.
      def feature_setting_name
        feature = workflow.foundational_flow&.resolve_ai_feature(
          current_user: workflow.user, container: workflow.project, additional_context: context[:additional_context]
        )&.to_s

        feature unless feature == ::Ai::ModelSelection::FeaturesConfigurable.workflow_feature_name.to_s
      end

      def reason_for_status(code)
        case code
        when 409 then :workflow_locked
        when 403 then :forbidden
        # Workhorse is draining or could not take the workflow lock; nothing started.
        when 503 then :workhorse_unavailable
        else :execute_workflow_failed
        end
      end

      def await_turn_end
        STATUS_POLL_ATTEMPTS.times do |attempt|
          workflow.reset

          return ServiceResponse.success(payload: { workflow: workflow }) if turn_ended?
          return incomplete_turn_response if workflow.status_terminal?

          sleep(STATUS_POLL_INTERVAL) if attempt < STATUS_POLL_ATTEMPTS - 1
        end

        incomplete_turn_response
      end

      def turn_ended?
        TURN_END_STATUS_GROUPS.include?(workflow.status_group)
      end

      def incomplete_turn_response
        ServiceResponse.error(
          message: "Workflow #{workflow.id} did not pause for the user, status: #{workflow.status_name}",
          reason: :flow_failed
        )
      end

      def request_url
        Gitlab::Utils.append_path(Gitlab.config.gitlab.url, format(EXECUTE_PATH, id: workflow.id))
      end

      # Workhorse's pre-authorization request to Rails forwards the original
      # request's method, rebased URL and headers, but never its body. Anything
      # the Rails :execute action reads through params must therefore be a query
      # parameter here; the body below is read only by Workhorse itself.
      def request_query
        {
          project_id: workflow.project_id,
          namespace_id: workflow.namespace_id,
          root_namespace_id: resource_parent.root_ancestor.id,
          workflow_definition: workflow.workflow_definition,
          ai_catalog_item_version_id: workflow.ai_catalog_item_version_id,
          environment: workflow.environment,
          client_type: CLIENT_TYPE,
          detached: (true if detached)
        }.compact
      end

      # camelCase because Workhorse decodes this as a protojson StartWorkflowRequest.
      # It carries no workflow ID: Workhorse takes that from the pre-authorization
      # response, since it authorizes nothing itself.
      def request_body
        {
          goal: goal,
          workflowDefinition: workflow.workflow_definition,
          clientVersion: CLIENT_VERSION,
          approval: approval,
          additional_context: wire_additional_context
        }.merge(flow_config_params).compact
      end

      # No standard_context_params: a Workhorse session has no workload branch.
      def wire_additional_context
        envelopes = ::Ai::DuoWorkflows::BuildAdditionalContextService.new(
          trigger_params: context.slice(:event_type, :triggering_conversation),
          additional_context: context[:additional_context],
          client_context: context[:client_context],
          resource: workflow.resource,
          foundational_flow: workflow.foundational_flow
        ).execute.payload[:context]

        envelopes.presence&.map { |envelope| ::Ai::DuoWorkflows::AdditionalContext::Envelope.to_wire(envelope) }
      end

      def flow_config_params
        params = workflow.foundational_flow_params

        {
          flowConfigId: params[:flow_config_id],
          flowConfigSchemaVersion: params[:flow_config_schema_version],
          flowVersion: params[:flow_version]
        }
      end

      def resource_parent
        workflow.resource_parent
      end
    end
  end
end
