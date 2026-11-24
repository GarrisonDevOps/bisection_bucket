# frozen_string_literal: true

class Groups::Security::ComplianceDashboardsController < Groups::ApplicationController
  include Groups::SecurityFeaturesHelper
  include ProductAnalyticsTracking

  DEFAULT_COMPLIANCE_TAB = 'compliance_status'
  LEGACY_DEFAULT_COMPLIANCE_TAB = 'standards_adherence'

  layout 'group'

  before_action :authorize_compliance_dashboard!

  before_action do
    push_frontend_ability(ability: :admin_compliance_framework, resource: group, user: current_user)

    push_licensed_feature(:group_level_compliance_adherence_report, group.root_ancestor)
  end

  track_internal_event :show,
    name: 'g_compliance_dashboard',
    additional_properties: ->(controller) { controller.additional_properties }

  feature_category :compliance_management

  def show; end

  def additional_properties
    { label: compliance_tab }
  end

  def vue_route
    params.permit(:vueroute)[:vueroute].presence || DEFAULT_COMPLIANCE_TAB
  end

  def compliance_tab
    case vue_route.split('/').first
    when LEGACY_DEFAULT_COMPLIANCE_TAB, DEFAULT_COMPLIANCE_TAB, nil, ''
      # We renamed the new compliance report when we added the new version
      'compliance_status'
    when 'violations'
      'violations'
    when 'frameworks'
      'frameworks'
    when 'projects'
      'projects'
    else
      'unknown_vue_tab_route'
    end
  end

  def tracking_namespace_source
    group
  end

  def tracking_project_source
    nil
  end
end
