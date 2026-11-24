# frozen_string_literal: true

class Admin::AuditLogsController < Admin::ApplicationController
  include Gitlab::Utils::StrongMemoize
  include AuditEvents::EnforcesValidDateParams
  include AuditEvents::AuditEventsParams
  include AuditEvents::Sortable
  include AuditEvents::DateRange
  include Gitlab::Tracking
  include ProductAnalyticsTracking
  include GovernUsageTracking

  before_action :check_license_admin_audit_event_available!

  track_event :index,
    name: 'i_compliance_audit_events',
    action: 'visit_instance_compliance_audit_events',
    label: 'redis_hll_counters.compliance.compliance_total_unique_counts_monthly',
    destinations: [:redis_hll, :snowplow]

  track_govern_activity 'audit_events', :index

  feature_category :audit_events

  PER_PAGE = 25

  def index
    @is_last_page = events.last_page?

    @events = AuditEventSerializer.new.represent(events)
    @audit_event_definitions = Gitlab::Audit::Type::Definition.names_with_category

    @entity = case audit_events_params[:entity_type]
              when 'User'
                user_entity
              when 'Project'
                Project.find_by_id(audit_events_params[:entity_id])
              when 'Group'
                Namespace.find_by_id(audit_events_params[:entity_id])
              end

    Gitlab::Tracking.event(self.class.name, 'search_audit_event', user: current_user)
  end

  def additional_properties_for_tracking
    return {} unless instance_active_frameworks?

    { with_active_compliance_frameworks: 'true' }
  end

  private

  def instance_active_frameworks?
    ::ComplianceManagement::ComplianceFramework::ProjectSettings.any?
  end

  def tracking_namespace_source
    nil
  end

  def tracking_project_source
    nil
  end

  def events
    strong_memoize(:events) do
      finder_params = audit_events_params.merge(
        pagination: 'offset',
        page: pagination_params[:page],
        per_page: PER_PAGE
      )
      finder = ::AuditEvents::CombinedAuditEventFinder.new(params: finder_params)
      result = finder.execute

      # Synthetic total_count for Kaminari pagination. The CombinedAuditEventFinder
      # cannot compute a real total count across multiple tables without an expensive
      # query. Instead, the finder fetches page_size + 1 records and returns
      # has_next_page. We derive a total_count that makes Kaminari's last_page?
      # return the correct value so the UI shows/hides the Next page button.
      total_count = if result[:has_next_page]
                      (result[:page] * result[:per_page]) + 1
                    elsif result[:records].empty?
                      1
                    else
                      ((result[:page] - 1) * result[:per_page]) + result[:records].size
                    end

      events_array = Kaminari.paginate_array(
        result[:records],
        total_count: total_count
      ).page(result[:page]).per(result[:per_page])

      Gitlab::Audit::Events::Preloader.preload!(events_array)

      events_array
    end
  end

  def check_license_admin_audit_event_available!
    render_404 unless License.feature_available?(:admin_audit_log)
  end

  def user_entity
    if audit_events_params[:entity_username].present?
      return User.find_by_username(audit_events_params[:entity_username])
    end

    User.find_by_id(audit_events_params[:entity_id])
  end
end
