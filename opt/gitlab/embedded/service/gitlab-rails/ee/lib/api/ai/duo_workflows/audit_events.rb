# frozen_string_literal: true

module API
  module Ai
    module DuoWorkflows
      class AuditEvents < ::API::Base
        include APIGuard

        allow_access_with_scope :ai_workflows

        feature_category :audit_events

        before { authenticate! }

        helpers ::API::Helpers::AiAuditEventIngestHelpers

        helpers do
          def find_workflow!(id)
            workflow = ::Ai::DuoWorkflows::Workflow.for_user_with_id!(current_user.id, id)
            return workflow if Ability.allowed?(current_user, :read_duo_workflow, workflow)

            forbidden!
          end
        end

        namespace :ai do
          namespace :duo_workflows do
            namespace :workflows do
              route_param :id, type: Integer do
                resource :audit_events do
                  # rubocop:disable API/DescriptionDetail -- internal endpoint, not part of the public API
                  desc 'Ingest AI audit events from Duo Workflow Service' do
                    success code: 202
                    failure [
                      { code: 400, message: 'Bad request' },
                      { code: 401, message: 'Unauthorized' },
                      { code: 403, message: 'Forbidden' },
                      { code: 404, message: 'Not found' },
                      { code: 429, message: 'Too many requests' }
                    ]
                    tags %w[gitlab_duo_workflows internal_operations]
                  end
                  # rubocop:enable API/DescriptionDetail
                  params do
                    requires :id, type: Integer, desc: 'ID of the workflow.'
                    max_events = ::Ai::DuoWorkflows::IngestAuditEventsService::MAX_EVENTS_PER_REQUEST
                    requires :events, type: Array, allow_blank: false, limit: max_events,
                      desc: "Array of CloudEvents v1.0 envelopes. Maximum #{max_events}." do
                      requires :id, type: String, desc: 'ID of the CloudEvent, as a UUID.'
                      requires :type, type: String, desc: 'Type of the event, for example `ai_llm_input_sent`.'
                      requires :source, type: String, desc: 'CloudEvent source.'
                      requires :time, type: DateTime, desc: 'Event timestamp from the gateway.'
                      optional :data, type: Hash, desc: 'Event-specific payload.'
                    end
                  end
                  route_setting :authorization, skip_granular_token_authorization: :ai_workflows_token_auth
                  post urgency: :low do
                    workflow = find_workflow!(params[:id])
                    # A check constraint gives every workflow exactly one of project and namespace.
                    top_level_namespace = workflow.resource_parent.root_ancestor

                    check_ai_audit_event_ingest_limit!(:ai_duo_workflow_audit_event_ingest,
                      scope: { user: current_user }, top_level_namespace: top_level_namespace)
                    check_ai_audit_event_ingest_limit!(:ai_audit_event_ingest_by_top_level_namespace,
                      scope: { namespace: top_level_namespace }, top_level_namespace: top_level_namespace,
                      cost: params[:events].size)

                    result = ::Ai::DuoWorkflows::IngestAuditEventsService.new(
                      workflow: workflow,
                      events: params[:events],
                      current_user: current_user
                    ).execute

                    if result.error?
                      render_api_error!(result.message, result.reason || :unprocessable_entity)
                    else
                      status 202
                      result.payload
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
end
