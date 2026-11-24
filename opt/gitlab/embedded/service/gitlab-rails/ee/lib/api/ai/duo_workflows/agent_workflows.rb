# frozen_string_literal: true

module API
  module Ai
    module DuoWorkflows
      # This endpoint is a restricted mirror of POST /ai/duo_workflows/workflows,
      # intended for agents to kick off foundational flows via an ai_workflows-scoped token.
      # It does not accept agent_privileges or pre_approved_agent_privileges, ensuring
      # agents cannot escalate their own privileges when creating workflows.
      class AgentWorkflows < ::API::Base
        include PaginationParams
        include APIGuard

        helpers ::API::Helpers::DuoWorkflowHelpers

        feature_category :duo_agent_platform
        urgency :low

        allow_access_with_scope :ai_workflows

        before do
          authenticate!
        end

        helpers do
          # Only the business logic flow is validated here; other flows keep this endpoint's behaviour.
          def validate_bl_security_goal!(workflow_definition, container)
            return unless workflow_definition == ::Ai::Catalog::FoundationalFlow::BL_SECURITY_FLOW_REFERENCE

            validate_flow_start_request!(workflow_definition, container, client_executed: false)
          end

          def create_workflow_params
            declared_params(include_missing: false).except(
              :start_workflow,
              :source_branch,
              :additional_context,
              :ai_catalog_item_consumer_id
            ).tap do |wrkf_params|
              if wrkf_params[:ai_catalog_item_version_id]
                wrkf_params[:ai_catalog_item_version] = ::Ai::Catalog::ItemVersion
                                                          .find(wrkf_params.delete(:ai_catalog_item_version_id))
              end

              if wrkf_params[:issue_id] && wrkf_params[:project_id]
                project = find_project!(wrkf_params[:project_id])
                wrkf_params[:issue] = project.issues.find_by_iid!(wrkf_params.delete(:issue_id))
              end

              if wrkf_params[:merge_request_id] && wrkf_params[:project_id]
                project = find_project!(wrkf_params[:project_id])
                wrkf_params[:merge_request] = project.merge_requests.find_by_iid!(wrkf_params.delete(:merge_request_id))
              end
            end
          end

          # Every caller is a running agent, so with chaining on, the request must come from its workflow.
          # The header is client-supplied, so the workflow is authorized before it is used.
          def parent_workflow_for_chaining!(container)
            return unless Feature.enabled?(:ai_flow_trigger_chaining, container.root_ancestor)

            parent_workflow = ::Ai::FlowTriggers::CallerContext.authorized_parent_workflow_for_request(current_user)
            return parent_workflow if parent_workflow

            forbidden!('An agent can only start a workflow from a workflow it is allowed to update')
          end

          params :workflow_params do
            optional :project_id, type: String, desc: 'ID or path of the project to associate the flow with.',
              documentation: { example: '1' }
            optional :namespace_id, type: String, desc: 'ID or path of the namespace to associate the flow with.',
              documentation: { example: '1' }
            optional :ai_catalog_item_consumer_id, type: Integer,
              desc: 'ID of the AI Catalog item consumer that determines which catalog item to run. Requires ' \
                '`project_id`. If `workflow_definition` is also provided, `ai_catalog_item_consumer_id` takes ' \
                'precedence.',
              documentation: { example: 1 }
            optional :start_workflow, type: Boolean,
              desc: 'If `true`, starts the workflow in a CI pipeline. This feature is experimental.',
              documentation: { example: true }
            optional :goal, type: String, desc: 'Goal of the workflow.',
              documentation: { example: 'Fix pipeline for merge request 1 in project 1' }
            optional :workflow_definition, type: String, desc: 'Workflow type based on its capability.',
              documentation: { example: 'software_developer' }
            optional :allow_agent_to_request_user, type: Boolean,
              desc: 'If `true`, Duo Agent Platform may stop to ask the user questions before proceeding. If `false`, ' \
                'Duo Agent Platform runs through the workflow without asking for user input. Defaults to `true`.',
              documentation: { example: true }
            optional :image, type: String, desc: 'Container image to use for running the workflow in CI pipeline.',
              documentation: { example: 'registry.gitlab.com/gitlab-org/duo-workflow/custom-image:latest' }
            optional :source_branch, type: String,
              desc: "Source branch for the CI pipeline. Defaults to the project's default branch.",
              documentation: { example: 'main' }
            optional :environment, type: String,
              values: ::Ai::DuoWorkflows::Workflow.environments.keys.map(&:to_s),
              desc: 'Environment for the workflow.',
              documentation: { example: 'web' }
            optional :ai_catalog_item_version_id, type: Integer,
              desc: 'ID of the AI Catalog item version that sourced the flow configuration used by the workflow.',
              documentation: { example: 1 }
            optional :additional_context, type: Array,
              desc: 'Additional context for the flow. Each element is an object with at least `Category` and ' \
                '`Content` keys. `Content` is a JSON-serialized string.',
              documentation: {
                example: '[{"Category": "agent_user_environment", "Content": "{\"merge_request_url\": ' \
                  'https://gitlab.com/project/-/merge_requests/1\"}", "Metadata": "{}"}]'
              } do
                requires :Category, type: String, desc: 'Category of the context detail.'
                requires :Content, type: String, desc: 'Content of the context detail.'
              end
            optional :issue_id, type: Integer,
              desc: 'Internal ID of the issue that the workflow is associated with. Requires `project_id`.',
              documentation: { example: 123 }
            optional :merge_request_id, type: Integer,
              desc: 'Internal ID of the merge request that the workflow is associated with. Requires `project_id`.',
              documentation: { example: 123 }
          end
        end

        namespace :ai do
          namespace :duo_workflows do
            namespace :agent_workflows do
              desc 'Create workflow persistence (agent-initiated, limited privileges)' do
                tags ['gitlab_duo_workflows']
                detail 'Accessible via ai_workflows scope token. ' \
                  'Does not accept agent_privileges or pre_approved_agent_privileges.'
                success code: 201
                failure [
                  { code: 400, message: 'Validation failed' },
                  { code: 401, message: 'Unauthorized' },
                  { code: 403, message: '403 Forbidden' },
                  { code: 404, message: 'Not found' },
                  { code: 422, message: 'Unprocessable entity' }
                ]
              end
              params do
                use :workflow_params
              end
              route_setting :authorization, skip_granular_token_authorization: :ai_workflows_oauth_auth
              route_setting :lifecycle, :experiment
              post do
                ::Gitlab::QueryLimiting.disable!(
                  'https://gitlab.com/gitlab-org/gitlab/-/issues/566195', new_threshold: 125
                )

                container = if params[:project_id]
                              find_project!(params[:project_id])
                            elsif params[:namespace_id]
                              find_workflow_namespace!(params[:namespace_id])
                            else
                              ::Ai::UserAuthorizer.for(current_user).default_duo_namespace
                            end

                if container.nil?
                  bad_request!('No default namespace found. Please provide project_id or namespace_id, ' \
                    'or configure a default Duo namespace.')
                end

                forbidden!('Access to the container is not allowed') unless container_access_allowed?(container)

                forbidden_if_identity_verification_required!(container)

                parent_workflow = parent_workflow_for_chaining!(container)

                if params[:ai_catalog_item_consumer_id]
                  unless container.is_a?(Project)
                    bad_request!('AI Catalog flows can only be executed in project context')
                  end

                  consumer = find_item_consumer!(params[:ai_catalog_item_consumer_id], container)
                  # Checked after authorization so the goal cannot probe for merge requests.
                  if Ability.allowed?(current_user, :execute_ai_catalog_item, consumer)
                    validate_bl_security_goal!(consumer.item.foundational_flow_reference, container)
                  end

                  require_repository_for_flow!(container) if can_execute_catalog_item?(consumer, container)

                  service_account = if consumer.project.present?
                                      consumer.parent_item_consumer&.service_account
                                    else
                                      consumer.service_account
                                    end

                  service_account = enforce_start_workflow_service_account(
                    service_account, container, consumer: consumer
                  )

                  flow_params = {
                    item_consumer: consumer,
                    service_account: service_account,
                    execute_workflow: params[:start_workflow].present?,
                    event_type: 'api_execution',
                    user_prompt: params[:goal],
                    source_branch: params[:source_branch],
                    additional_context: params[:additional_context],
                    parent_workflow: parent_workflow
                  }

                  result = ::Ai::Catalog::Flows::ExecuteService.new(
                    project: container,
                    current_user: current_user,
                    params: flow_params
                  ).execute

                  render_catalog_flow_error!(result)

                  workflow = result.payload[:workflow]
                  workload_id = result.payload[:workload_id]

                  present workflow, with: ::API::Entities::Ai::DuoWorkflows::Workflow,
                    workload: { id: workload_id, message: result.message }
                else
                  workflow_params = create_workflow_params

                  # A running agent is the caller here, so the run is always background.
                  # This endpoint's caller holds an ai_workflows-scoped token rather than a
                  # user's own, so it can never be the one performing the run.
                  execution = authorize_flow_execution!(
                    workflow_params, container,
                    caller_can_execute: false,
                    start_workflow: params[:start_workflow].present?,
                    item_consumer_id: params[:ai_catalog_item_consumer_id]
                  )
                  validate_bl_security_goal!(workflow_params[:workflow_definition], container)
                  require_repository_for_flow!(container)

                  workflow_params[:service_account] = enforce_start_workflow_service_account(
                    workflow_params[:service_account], container
                  )

                  workflow_params[:agent_privileges] = ::Ai::DuoWorkflows::Workflow::AgentPrivileges::DEFAULT_PRIVILEGES
                  foundational_flow =
                    ::Ai::DuoWorkflows::DeclaredPrivileges.foundational_flow(workflow_params[:workflow_definition])

                  if foundational_flow
                    workflow_params[:pre_approved_agent_privileges] =
                      ::Ai::DuoWorkflows::Workflow.column_defaults['pre_approved_agent_privileges']
                    ::Ai::DuoWorkflows::DeclaredPrivileges.apply!(workflow_params, foundational_flow)
                  end

                  workflow_params[:parent_workflow] = parent_workflow if parent_workflow

                  service = ::Ai::DuoWorkflows::CreateWorkflowService.new(
                    container: container, current_user: current_user, params: workflow_params,
                    execution: execution)

                  result = service.execute

                  forbidden!(result.message) if result.error? && result.http_status == :forbidden
                  not_found!(result.message) if result.error? && result.http_status == :not_found
                  if result.error? && result.http_status == :payment_required
                    forbidden!(::API::Helpers::DuoWorkflowHelpers::INSUFFICIENT_CREDITS_MESSAGE)
                  end

                  if result.error? && result.http_status == :unprocessable_entity
                    render_api_error!(result[:message], :unprocessable_entity)
                  end

                  bad_request!(result[:message]) if result[:status] == :error

                  push_ai_gateway_headers(scope: container,
                    subject: workflow_params[:service_account] || current_user)

                  if params[:start_workflow].present?
                    response = ::Ai::DuoWorkflows::StartWorkflowService.new(
                      workflow: result[:workflow],
                      params: start_workflow_params(result[:workflow].id, container: container,
                        service_account: workflow_params[:service_account],
                        workflow_definition: workflow_params[:workflow_definition])
                    ).execute

                    if response.error?
                      status_code = case response.reason
                                    when :unprocessable_entity
                                      :unprocessable_entity
                                    when :feature_unavailable, :invalid_service_account
                                      :forbidden
                                    when :workload_failure, :repository_empty
                                      :unprocessable_entity
                                    else
                                      :internal_server_error
                                    end

                      if response.reason == :repository_empty
                        render_structured_api_error!(
                          { 'message' => response.message, 'reason' => 'repository_empty' },
                          status_code
                        )
                      else
                        render_api_error!(response.message, status_code)
                      end
                    else
                      workload_id = response.payload && response.payload[:workload_id]
                      message = response.message
                    end
                  end

                  present result[:workflow], with: ::API::Entities::Ai::DuoWorkflows::Workflow,
                    workload: { id: workload_id, message: message }
                end
              end
            end
          end
        end
      end
    end
  end
end
