# frozen_string_literal: true

module API
  module Ai
    module ExternalAgents
      class AuditEvents < ::API::Base
        feature_category :software_composition_analysis

        before do
          authenticate!
        end

        helpers ::API::Helpers::AiAuditEventIngestHelpers

        # About enough for a tool output or model response excerpted as Duo Agent Platform does it,
        # the first and last 8 KiB of the text, with the event's other details. Measured as JSON, so
        # escaped characters count more than once and a client must check the encoded size.
        MAX_DETAILS_BYTES = 32.kilobytes

        helpers do
          def audit_event_rejection(event)
            occurred_at = event[:occurred_at]
            return :occurred_at_in_future if occurred_at > 1.hour.from_now
            return :occurred_at_too_old if occurred_at < 90.days.ago

            :details_too_large if event[:details].to_json.bytesize > MAX_DETAILS_BYTES
          end

          def track_audit_events(event_name, **additional_properties)
            ::Gitlab::InternalEvents.track_event(event_name, category: 'API::Ai::ExternalAgents::AuditEvents',
              user: current_user, project: user_project, additional_properties: additional_properties)
          end
        end

        REJECTION_MESSAGES = {
          occurred_at_in_future: 'occurred_at cannot be more than 1 hour in the future',
          occurred_at_too_old: 'occurred_at cannot be more than 90 days in the past',
          details_too_large: 'details payload too large (max 32 KB per event)'
        }.freeze

        resource :projects, requirements: NAMESPACE_OR_PROJECT_REQUIREMENTS do
          before do
            find_project!(params[:id])
            not_found! unless Feature.enabled?(:ai_agent_session_tracking, user_project)

            forbidden! unless user_project.licensed_feature_available?(:ai_catalog)

            if ::Ai::Governance::AgentGovernance.report_disabled_to?(current_user, user_project)
              not_found!('AI agent governance')
            end
          end

          namespace ':id/ai_agent/audit_events' do
            desc 'Ingest external agent audit events.' do
              detail 'Accepts a batch of up to 500 audit events for an external agent session. ' \
                'Events are validated, deduplicated by cloud_event_id, and enqueued for storage.'
              success code: 202, message: 'Accepted'
              failure [
                { code: 400, message: 'Bad request' },
                { code: 401, message: 'Unauthorized' },
                { code: 403, message: 'Forbidden' },
                { code: 404, message: 'Not found' },
                { code: 429, message: 'Too many requests' }
              ]
              tags %w[projects ai_agent_audit_events]
            end

            max_events = ::Ai::DuoWorkflows::IngestAuditEventsService::MAX_EVENTS_PER_REQUEST

            params do
              requires :session_id, type: Integer,
                desc: 'The session ID to associate events with.'
              requires :events, type: Array,
                limit: max_events,
                allow_blank: false,
                desc: "Batch of audit events. Maximum #{max_events}." do
                requires :event_name, type: String,
                  desc: 'The audit event type.',
                  allow_blank: false
                requires :cloud_event_id, type: String,
                  desc: 'Unique CloudEvent ID for deduplication.',
                  allow_blank: false,
                  regexp: /\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/i
                requires :occurred_at, type: DateTime,
                  desc: 'When the event occurred (ISO 8601).'
                optional :details, type: Hash,
                  desc: 'Additional event details.',
                  coerce_with: ->(val) { val.to_h },
                  default: {}
              end
            end

            route_setting :lifecycle, :experiment
            route_setting :tier, :premium
            route_setting :authorization, permissions: :create_ai_agent_audit_event, boundary_type: :project

            post do
              authorize! :create_ai_agent_audit_event, user_project
              check_rate_limit!(:ai_agent_audit_event_ingest, scope: { user: current_user, project: user_project })

              rejection = params[:events].lazy.filter_map { |event| audit_event_rejection(event) }.first
              if rejection
                track_audit_events('reject_external_agent_audit_events', property: rejection.to_s,
                  value: params[:events].size)
                bad_request!(REJECTION_MESSAGES[rejection])
              end

              session = ::Ai::Governance::Session.find_external_session(
                namespace_id: user_project.project_namespace_id,
                session_id: params[:session_id]
              )

              not_found!('Session') unless session
              forbidden! unless session.user_id == current_user.id

              check_ai_audit_event_ingest_limit!(:ai_audit_event_ingest_by_top_level_namespace,
                scope: { namespace: user_project.root_ancestor }, top_level_namespace: user_project.root_ancestor,
                cost: params[:events].size)

              cloud_events = params[:events].map do |event|
                {
                  id: event[:cloud_event_id],
                  type: event[:event_name],
                  time: event[:occurred_at].iso8601,
                  data: event[:details] || {}
                }
              end

              result = ::Ai::DuoWorkflows::IngestAuditEventsService.new(
                workflow: session,
                governance_session_id: session.id,
                events: cloud_events,
                current_user: current_user,
                ip_address: Gitlab::RequestContext.instance.client_ip
              ).execute

              if result.success?
                track_audit_events('post_external_agent_audit_events', label: session.agent_type,
                  value: result.payload[:count])
                ::Ai::ExternalAgents::AgentIdentity.record_sync(session.agent_identity_id)
                status :accepted
                present result.payload
              elsif result.reason == :bad_request
                bad_request!(result.message)
              else
                Gitlab::AppLogger.error(
                  message: 'Failed to ingest audit events',
                  project_id: user_project.id,
                  user_id: current_user.id
                )
                render_api_error!('Failed to process audit events', 500)
              end
            end
          end
        end
      end
    end
  end
end
