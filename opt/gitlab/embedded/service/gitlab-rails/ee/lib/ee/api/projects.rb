# frozen_string_literal: true

module EE
  module API
    module Projects
      extend ActiveSupport::Concern

      prepended do
        resource :projects do
          segment ':id/audit_events', feature_category: :audit_events do
            before do
              authorize! :read_audit_event, user_project
              check_audit_events_available!(user_project)
              check_rate_limit!(:project_audit_events_api, scope: { user: current_user, project: user_project })
              increment_unique_values('a_compliance_audit_events_api', current_user.id)

              ::Gitlab::Tracking.event(
                'EE::API::Projects',
                'project_audit_event_request',
                user: current_user,
                project: user_project,
                namespace: user_project.namespace,
                context: [
                  ::Gitlab::Tracking::ServicePingContext
                    .new(data_source: :redis_hll, event: 'a_compliance_audit_events_api')
                    .to_context
                ]
              )
            end

            desc 'List all project audit events' do
              detail 'Lists all audit events for a specified project. Users with at least the Maintainer role get ' \
                'the audit events of all users. Users with the Developer role get only the events of their own ' \
                'actions. Offset-based pagination was deprecated in GitLab 17.8 and is planned for removal in ' \
                'GitLab 19.0. Use keyset-based pagination instead. This change is a breaking change.'
              success ::API::Entities::AuditEvent
              is_array true
              tags %w[projects]
            end
            params do
              optional :created_after,
                type: DateTime,
                desc: 'Return project audit events created on or after the specified time.',
                documentation: { type: 'dateTime', example: '2016-01-19T09:05:50.355Z' }
              optional :created_before,
                type: DateTime,
                desc: 'Return project audit events created on or before the specified time.',
                documentation: { type: 'dateTime', example: '2016-01-19T09:05:50.355Z' }

              use :pagination
            end
            route_setting :tier, :premium
            route_setting :authorization, permissions: :read_audit_event, boundary_type: :project
            get '/', feature_category: :audit_events, urgency: :low do
              audit_event_finder_params[:optimize_offset] = true

              if params[:pagination] == 'keyset'
                params[:cursor] =
                  enrich_audit_event_cursor(params[:cursor], user_project)
                limit_keyset_per_page!
              end

              audit_events = ::AuditEvents::ProjectAuditEventFinder.new(
                project: user_project,
                params: audit_event_finder_params
              ).execute

              present paginate_with_strategies(audit_events), with: ::API::Entities::AuditEvent
            end

            desc 'Retrieve a project audit event' do
              detail 'Retrieves an audit event for a specified project. Only available to users with at least the ' \
                'Developer role for the project.'
              success ::API::Entities::AuditEvent
              tags %w[projects]
            end
            params do
              requires :audit_event_id, type: Integer, desc: 'ID of the audit event.'
            end
            route_setting :tier, :premium
            route_setting :authorization, permissions: :read_audit_event, boundary_type: :project
            get '/:audit_event_id', feature_category: :audit_events, urgency: :low do
              # rubocop: disable CodeReuse/ActiveRecord, Rails/FindById -- This is not `find_by!` from ActiveRecord
              audit_event = ::AuditEvents::ProjectAuditEventFinder.new(
                project: user_project,
                params: audit_event_finder_params
              ).find_by!(id: params[:audit_event_id])
              # rubocop: enable CodeReuse/ActiveRecord, Rails/FindById
              present audit_event, with: ::API::Entities::AuditEvent
            end
          end
        end

        helpers do
          include ::API::Helpers::AuditEventsCursorHelper

          extend ::Gitlab::Utils::Override

          override :verify_update_project_attrs!
          def verify_update_project_attrs!(project, attrs)
            super

            verify_mirror_attrs!(project, attrs)
            validate_git_import_url!(attrs[:import_url])
            verify_issuable_default_templates_attrs!(project, attrs)
            verify_merge_pipelines_attrs!(project, attrs)
            restrict_attrs_for_sec_ai_workflow_setting!(project, attrs)
          end

          override :authorize_project_update!
          def authorize_project_update!(project)
            return super if can?(current_user, :admin_project, project)
            return if can_update_sec_ai_workflow_settings?(project)

            forbidden!
          end

          def can_update_sec_ai_workflow_settings?(project)
            can?(current_user, :update_sec_ai_workflow_settings, project)
          end

          override :verify_project_filters!
          def verify_project_filters!(attrs)
            super

            attrs.delete(:include_hidden) unless current_user&.can_admin_all_resources?
          end

          # Deprecated: https://gitlab.com/gitlab-org/gitlab/-/issues/494294
          def verify_mirror_attrs!(project, attrs)
            unless can?(current_user, :admin_mirror, project)
              ::Projects::UpdateService::PULL_MIRROR_ATTRIBUTES.each do |attr_name|
                attrs.delete(attr_name)
              end
            end
          end

          def verify_issuable_default_templates_attrs!(project, attrs)
            unless project.feature_available?(:issuable_default_templates)
              attrs.delete(:issues_template)
              attrs.delete(:merge_requests_template)
            end
          end

          def verify_merge_pipelines_attrs!(project, attrs)
            attrs.delete(:merge_pipelines_enabled) unless project.feature_available?(:merge_pipelines)
            attrs.delete(:merge_trains_enabled) unless project.feature_available?(:merge_trains)
            attrs.delete(:merge_trains_skip_train_allowed) unless project.feature_available?(:merge_trains)
            attrs.delete(:merge_train_enforcement) unless project.feature_available?(:merge_trains)
            attrs.delete(:max_pipelines_per_merge_train) unless project.feature_available?(:merge_trains)
          end

          def check_audit_events_available!(project)
            forbidden! unless project.feature_available?(:audit_events)
          end

          def audit_event_finder_params
            params
              .slice(:created_after, :created_before, :pagination)
              .then { |params| filter_by_author(params) }
          end

          def filter_by_author(params)
            can?(current_user, :read_any_audit_event, user_project) ? params : params.merge(author_id: current_user.id)
          end
        end
      end
    end
  end
end
