# frozen_string_literal: true

# EE:Self Managed
class Admin::SubscriptionsController < Admin::ApplicationController
  include ::Admin::LicenseRequest

  respond_to :html

  feature_category :consumables_cost_management, [:billable_usage]
  feature_category :plan_provisioning
  urgency :low

  authorize! :read_admin_subscription, only: [:show, :billable_usage]

  before_action :require_license, only: :billable_usage
  before_action :verify_report_available!, only: :billable_usage

  private

  def verify_report_available!
    render_404 unless ::Utilization::BillableUsage::Exports::Availability.enabled?
  end
end
