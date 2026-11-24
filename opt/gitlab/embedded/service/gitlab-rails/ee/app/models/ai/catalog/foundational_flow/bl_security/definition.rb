# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      module BlSecurity
        module Definition
          module_function

          REFERENCE = 'bl_security/experimental'
          SCANNER_EXTERNAL_ID = 'gitlab_bl_security_analyzer'

          # Returns [pipeline, merge_request] for a goal: an MR IID, or a pipeline URL
          # (what GoalTemplates::BlSecurity emits for fork MRs and MR-less pipelines).
          GOAL_RESOLVER = ->(project:, goal:) do
            goal = goal.to_s
            next [nil, project.merge_requests.find_by_iid(goal)] if goal.match?(/\A\d+\z/)

            pipelines_url = "#{::Gitlab::Routing.url_helpers.project_url(project)}/-/pipelines/"
            pipeline_id = goal.delete_prefix(pipelines_url)
            # rubocop:disable Database/AvoidUnpartitionedCiRelations -- the goal has only a pipeline id, no partition
            pipeline = project.all_pipelines.find_by_id(pipeline_id) if pipeline_id.match?(/\A\d+\z/)
            # rubocop:enable Database/AvoidUnpartitionedCiRelations
            [pipeline, pipeline && ::Ai::Catalog::GoalTemplates::BlSecurity.merge_request_for(pipeline)]
          end
          private_constant :GOAL_RESOLVER

          # Why a digit-only goal (an MR IID) is refused: no such merge request, or not open.
          MERGE_REQUEST_GOAL_ERROR = ->(goal, merge_request) do
            next unless goal.to_s.match?(/\A\d+\z/)
            next 'Merge request not found' if merge_request.nil?

            'The merge request is not open' unless merge_request.opened?
          end
          private_constant :MERGE_REQUEST_GOAL_ERROR

          # Whether the namespace can list and attach Business logic scan profiles: the flow is on and,
          # while it is beta, so is the root group's Experiment and beta features setting.
          def scan_profiles_enabled_for?(namespace)
            flow = ::Ai::Catalog::FoundationalFlow.bl_security_experimental
            flow.enabled_for?(namespace) && (!flow.beta? || namespace.root_ancestor.duo_beta_flows_enabled?)
          end

          # Whether to promote BLSA to this namespace with the "Explore what's new" spotlight:
          # Ultimate, offered on this deployment (GitLab.com or Dedicated), and not already enabled.
          # Unlike scan_profiles_enabled_for?, this does not require the Experiment and beta features
          # setting - the spotlight's own job is to drive that opt-in, not assume it already happened.
          def spotlight_eligible_for?(namespace)
            root = namespace.root_ancestor
            flow = ::Ai::Catalog::FoundationalFlow.bl_security_experimental
            root.licensed_feature_available?(:ai_features) &&
              flow.available_on_current_deployment? &&
              gitlab_com_or_dedicated? &&
              !flow.enabled_for?(root)
          end

          # The spotlight's copy and request-access flow assume GitLab.com or Dedicated.
          # BLSA's `available_on` also lists :self_managed, but that's for the scan-execution
          # gate elsewhere, not this promo, so it can't be used here to exclude Self-Managed.
          def gitlab_com_or_dedicated?
            ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) ||
              ::Gitlab::Dedicated.feature_available?(:ai_flow_enablement)
          end

          def configuration
            {
              foundational_flow_reference: REFERENCE,
              goal_templates: ::Ai::Catalog::GoalTemplates::BlSecurity,
              # Findings are published as a SAST report, so they reach the
              # Vulnerability Report like any other analyzer's.
              report_artifacts: { sast: ['gl-sast-report.json'] },
              # Customers see the finished findings, not the model's intermediate output.
              content_retention: 'metadata',
              # Only on success: pipeline_hooks fires on every status change. A retried job
              # can still send a second success event (deduplicated by RunEligibility). Not
              # running: transient and racy; pending is not an allowed filter value.
              # Trade-off: failed pipelines are not scanned.
              default_trigger_filter: {
                'pipeline_hooks' => {
                  'match' => 'all',
                  'rules' => [
                    { 'field' => 'object_attributes.status', 'operator' => 'eq', 'value' => 'success' }
                  ]
                }
              },
              display_name: s_(
                "FoundationalFlow|Business Logic Security Scan"
              ),
              description: s_(
                "FoundationalFlow|Scan the repository for business logic security vulnerabilities."
              ),
              avatar: "security-flow.png",
              feature_maturity: "beta",
              feature_flag: "bl_security_analyzer",
              ai_feature: "bl_security",
              # BLSA jobs run only GitLab-controlled code, on a GitLab-hosted runner where one exists
              # (not on Self-Managed, where the instance's own runners take the job).
              gitlab_hosted_runner_only: true,
              agent_privileges: [
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_FILES,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_ONLY_GITLAB,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::RUN_COMMANDS,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::USE_GIT
              ],
              environment: "web",
              ultimate_only: true,
              available_on: %i[gitlab_com self_managed dedicated_enabled_instances],
              triggers: [::Ai::FlowTrigger::EVENT_TYPES[:pipeline_hooks]],
              # No flow schedules: default branches belong to scan execution policies.
              supported_events: [
                ::Ai::FlowTrigger::EVENT_TYPES[:pipeline_hooks], ::Ai::FlowTrigger::EVENT_TYPES[:security_policy]
              ],
              # MR pipelines and non-default-branch push pipelines, like the CI analyzers.
              # A push pipeline runs only if it is an open MR's head pipeline (see
              # start_request_validator). Child pipelines and other sources are excluded.
              # The trigger filter also applies (success only).
              precondition: {
                'match' => 'all',
                'rules' => [
                  {
                    'field' => 'object_attributes.source', 'operator' => 'in', 'value' => %w[merge_request_event push]
                  },
                  { 'field' => 'object_attributes.default_branch', 'operator' => 'eq', 'value' => false }
                ]
              },
              # A run started from the API or Duo Chat names only the merge request IID.
              # Check out an open, same-project merge request's source branch.
              source_branch_resolver: ->(project:, goal:) do
                next unless goal.to_s.match?(/\A\d+\z/)

                merge_request = project.merge_requests.opened.find_by_iid(goal.to_s)
                merge_request.source_branch if merge_request && !merge_request.for_fork?
              end,
              # Triggered runs need an attached Business Logic scan profile.
              run_eligibility_resolver: RunEligibility,
              additional_context_resolver: Context,
              # Refused before a workflow is created:
              # - a merge request IID that matches no open merge request in the project.
              # - a branch pipeline that is not an open merge request's head pipeline.
              # - a fork's merge request: the workload checks out the source branch
              #   in the pipeline's project, so in the target project it would scan
              #   the default branch under the merge request's name.
              # - a merge request that only deletes files: a merge request run scans
              #   only the files it changes (see Context).
              start_request_validator: ->(container:, goal:, additional_context:, client_executed:) do
                next unless container.is_a?(::Project)

                flow = ::Ai::Catalog::FoundationalFlow.bl_security_experimental
                next unless flow.enabled_for?(container.root_ancestor)

                pipeline, merge_request = GOAL_RESOLVER.call(project: container, goal: goal)

                goal_error = MERGE_REQUEST_GOAL_ERROR.call(goal, merge_request)
                if goal_error
                  ::Gitlab::AppJsonLogger.info(
                    message: "Business logic security scan not started: #{goal_error.downcase}",
                    project_id: container.id,
                    goal: goal.to_s
                  )

                  next ServiceResponse.error(message: goal_error, reason: :invalid_goal)
                end

                if pipeline&.push? && merge_request.nil?
                  ::Gitlab::AppJsonLogger.info(
                    message: 'Business logic security scan not started: ' \
                      'pipeline is not the head pipeline of an open merge request',
                    project_id: container.id,
                    goal: goal.to_s
                  )

                  next ServiceResponse.error(
                    message: 'The pipeline is not the head pipeline of an open merge request',
                    reason: :no_merge_request
                  )
                end

                if merge_request&.for_fork?
                  ::Gitlab::AppJsonLogger.info(
                    message: 'Business logic security scan not started: merge request is from a fork',
                    project_id: container.id,
                    merge_request_id: merge_request.id,
                    goal: goal.to_s
                  )

                  next ServiceResponse.error(
                    message: 'Merge requests from forks are not scanned',
                    reason: :fork_merge_request
                  )
                end

                next unless TargetFiles.for_goal(project: container, goal: goal).paths == []

                ::Gitlab::AppJsonLogger.info(
                  message: 'Business logic security scan not started: merge request has no added or modified files',
                  project_id: container.id,
                  goal: goal.to_s
                )

                ServiceResponse.error(
                  message: 'The merge request has no added or modified files to scan',
                  reason: :no_files_to_scan
                )
              end
            }
          end
        end
      end
    end
  end
end
