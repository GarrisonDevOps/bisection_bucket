# frozen_string_literal: true

require 'gitlab-http'
require_relative 'gitlab_api_helper'

module Keeps
  module Helpers
    # Runs a Duo Agent Platform flow session against a pushed branch and waits for it to finish.
    #
    # Unlike AiEditor, which patches one file per LLM call, the session gets the whole repository and
    # its own toolchain, so it can find and remove code that never mentions the thing being removed.
    class DuoWorkflowEditor
      Error = Class.new(StandardError)

      API_HOST = 'https://gitlab.com'
      CREATE_WORKFLOW_PATH = '/api/v4/ai/duo_workflows/workflows'
      GRAPHQL_PATH = '/api/graphql'
      DEFAULT_PROJECT_PATH = 'gitlab-org/gitlab'
      WORKFLOW_DEFINITION = 'software_development'
      # Runs the session in a CI pipeline rather than an IDE. See Ai::DuoWorkflows::Workflow::ENVIRONMENTS_FROM_PIPELINE.
      ENVIRONMENT = 'ambient'
      TERMINAL_STATUSES = %w[FINISHED FAILED STOPPED].freeze
      SUCCESS_STATUS = 'FINISHED'
      # A session in either group is parked waiting for a human (tool-call or plan approval, input,
      # or a resume) and will not progress on its own; an unattended run has no one to provide that,
      # so we stop rather than poll until the timeout. Using the status group rather than individual
      # statuses covers the whole class, including statuses added later. See
      # Ai::DuoWorkflows::Workflow::GROUPED_STATUSES.
      STUCK_STATUS_GROUPS = %w[AWAITING_INPUT PAUSED].freeze
      # AgentPrivileges ids from ee/app/models/ai/duo_workflows/workflow.rb: read/write files (1),
      # run commands (4), use git (5), read-only files (8). Granting and pre-approving the same set
      # keeps the session non-interactive so it never parks in a STUCK_STATUS_GROUPS state.
      AGENT_PRIVILEGES = [1, 4, 5, 8].freeze
      POLL_INTERVAL_SECONDS = 30
      DEFAULT_TIMEOUT_SECONDS = 3600

      WORKFLOW_STATUS_QUERY = <<~GRAPHQL
        query($workflowId: AiDuoWorkflowsWorkflowID!) {
          duoWorkflowWorkflows(workflowId: $workflowId) {
            nodes { id status statusGroup }
          }
        }
      GRAPHQL

      attr_reader :logger, :project_path, :timeout_seconds

      def initialize(logger:, project_path: nil, timeout_seconds: nil)
        @logger = logger
        @project_path = project_path || ENV['DUO_WORKFLOW_PROJECT_PATH'] || DEFAULT_PROJECT_PATH
        @timeout_seconds = timeout_seconds || env_timeout_seconds
        @token = ENV['DUO_WORKFLOW_API_TOKEN'] || ENV['HOUSEKEEPER_GITLAB_API_TOKEN']

        # The session-create REST call only accepts the api scope; ai_workflows works for the
        # GraphQL poll but is rejected by POST /ai/duo_workflows/workflows.
        raise ArgumentError, 'A GitLab API token with the api scope is required' if @token.nil?
      end

      # Returns true when the session finished successfully.
      def run(goal:, source_branch:)
        workflow_id = start_workflow(goal, source_branch)
        return false unless workflow_id

        logger.puts "Started Duo Workflow session #{workflow_id} on branch #{source_branch}"

        wait_for_completion(workflow_id)
      end

      private

      attr_reader :token

      # A malformed env value parses to 0, which would start a session and then abandon it on the
      # first poll; fall back to the default instead.
      def env_timeout_seconds
        seconds = ENV.fetch('DUO_WORKFLOW_TIMEOUT_SECONDS', DEFAULT_TIMEOUT_SECONDS).to_i
        seconds > 0 ? seconds : DEFAULT_TIMEOUT_SECONDS
      end

      def start_workflow(goal, source_branch)
        response = post(CREATE_WORKFLOW_PATH,
          project_id: project_path,
          goal: goal,
          workflow_definition: WORKFLOW_DEFINITION,
          environment: ENVIRONMENT,
          source_branch: source_branch,
          agent_privileges: AGENT_PRIVILEGES,
          pre_approved_agent_privileges: AGENT_PRIVILEGES,
          allow_agent_to_request_user: false,
          start_workflow: true
        )

        unless response.success?
          logger.puts "Failed to start Duo Workflow session: #{response.code} #{response.body}"
          return
        end

        parse(response.body)&.dig(:id)
      end

      def wait_for_completion(workflow_id)
        deadline = Time.now + timeout_seconds

        while deadline.future?
          sleep(POLL_INTERVAL_SECONDS)

          state = workflow_state(workflow_id)
          next unless state

          status = state[:status]

          if STUCK_STATUS_GROUPS.include?(state[:statusGroup].to_s)
            logger.puts "Duo Workflow session #{workflow_id} is parked in #{status} waiting for human input, " \
              "which an unattended run cannot provide; aborting. " \
              "Check agent_privileges/pre_approved_agent_privileges."
            return false
          end

          next unless TERMINAL_STATUSES.include?(status)

          logger.puts "Duo Workflow session #{workflow_id} ended with status #{status}"
          return status == SUCCESS_STATUS
        end

        # No public API to stop a session, so the session may still push later; the keep deletes the
        # branch on a failed handoff to neutralise the race. See gitlab-org/gitlab#616264.
        logger.puts "Duo Workflow session #{workflow_id} timed out after #{timeout_seconds}s"
        false
      end

      def workflow_state(workflow_id)
        response = post(GRAPHQL_PATH,
          query: WORKFLOW_STATUS_QUERY,
          variables: { workflowId: "gid://gitlab/Ai::DuoWorkflows::Workflow/#{workflow_id}" }
        )
      rescue StandardError => e
        # A transient failure (connection reset, DNS blip, timeout) is not a session failure:
        # returning nil polls again rather than discarding a session that may still be running.
        logger.puts "Could not poll Duo Workflow session #{workflow_id}: #{e.class}: #{e.message}"
        nil
      else
        unless response.success?
          logger.puts "Failed to poll Duo Workflow session #{workflow_id}: #{response.code} #{response.body}"
          return
        end

        parse(response.body)&.dig(:data, :duoWorkflowWorkflows, :nodes, 0)
      end

      # A malformed body must not escape: it would otherwise abort the whole housekeeper run from
      # inside the polling loop, rather than failing this one flag.
      def parse(body)
        Gitlab::Json.safe_parse(body, symbolize_names: true)
      rescue StandardError => e
        logger.puts "Could not parse Duo Workflow API response: #{e.class}: #{e.message}"
        nil
      end

      def api_helper
        @api_helper ||= GitlabApiHelper.new(token: token)
      end

      def post(path, **body)
        api_helper.post("#{API_HOST}#{path}", body)
      end
    end
  end
end
