# frozen_string_literal: true

module API
  class AuditEvents < ::API::Base
    include ::API::PaginationParams

    urgency :low

    feature_category :audit_events

    before do
      authenticated_as_admin!
      forbidden! unless ::License.feature_available?(:admin_audit_log)
      check_rate_limit!(:audit_events_api, scope: { user: current_user })
      increment_unique_values('a_compliance_audit_events_api', current_user.id)

      ::Gitlab::Tracking.event(
        'API::AuditEvents',
        :admin_audit_event_request,
        user: current_user,
        context: [::Gitlab::Tracking::ServicePingContext.new(data_source: :redis_hll, event: 'a_compliance_audit_events_api').to_context]
      )
    end

    resources :audit_events do
      desc 'List all instance audit events' do
        detail 'Lists all available instance audit events, limited to a maximum of 30 days for each query. ' \
          'Offset-based pagination was deprecated in GitLab 17.8 and is planned for removal in GitLab 20.0. ' \
          'Use keyset-based pagination instead. This change is a breaking change.'
        success ::API::Entities::AuditEvent
        is_array true
        tags %w[audit_events]
      end
      params do
        optional :entity_type, type: String, desc: 'Return audit events for the specified entity type.', values: ::AuditEvents::BaseAuditEventFinder::VALID_ENTITY_TYPES
        optional :entity_id, type: Integer, desc: 'Return audit events for the specified entity ID. Requires the `entity_type` attribute.'
        given :entity_id do
          requires :entity_type, type: String, desc: 'Return audit events for the specified entity type.'
        end
        optional :created_after,
          type: DateTime,
          desc: 'Return audit events created on or after the specified time.',
          documentation: { type: 'dateTime', example: '2016-01-19T09:05:50.355Z' }
        optional :created_before,
          type: DateTime,
          desc: 'Return audit events created on or before the specified time.',
          documentation: { type: 'dateTime', example: '2016-01-19T09:05:50.355Z' }

        use :pagination
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :read_audit_event, boundary_type: :instance, assignable_when: [:admin]
      get do
        finder_params = params.merge(pagination: params[:pagination] || 'offset')
        finder = ::AuditEvents::CombinedAuditEventFinder.new(params: finder_params)
        result = finder.execute

        if params[:pagination] == 'keyset'
          if result[:cursor_for_next_page]
            Gitlab::Pagination::Keyset::HeaderBuilder
              .new(self)
              .add_next_page_header({ cursor: result[:cursor_for_next_page] })
          end
        else
          current_page = result[:page]
          per_page = result[:per_page]

          next_page = result[:records].size == per_page ? current_page + 1 : nil
          prev_page = current_page > 1 ? current_page - 1 : nil

          Gitlab::Pagination::OffsetHeaderBuilder.new(
            request_context: self,
            per_page: per_page,
            page: current_page,
            next_page: next_page,
            prev_page: prev_page
          ).execute(data_without_counts: true)
        end

        present result[:records], with: ::API::Entities::AuditEvent
      end

      desc 'Retrieve an instance audit event' do
        detail 'Retrieves a specified instance audit event.'
        success ::API::Entities::AuditEvent
        tags %w[audit_events]
      end
      params do
        requires :id, type: Integer, desc: 'ID of the audit event.'
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :read_audit_event, boundary_type: :instance, assignable_when: [:admin]
      get ':id' do
        audit_event = ::AuditEvents::CombinedAuditEventFinder.new.find(params[:id])

        present audit_event, with: ::API::Entities::AuditEvent
      end
    end
  end
end
