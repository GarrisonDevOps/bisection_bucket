# frozen_string_literal: true

class Admin::PushRulesController < Admin::ApplicationController
  before_action :check_push_rules_available!
  before_action :set_push_rule, except: :update
  before_action :set_application_setting

  respond_to :html

  feature_category :source_code_management

  def show; end

  def update
    service_response = PushRules::CreateOrUpdateService.new(
      container: admin_current_organization,
      current_user: current_user,
      params: push_rule_params
    ).execute

    @push_rule = service_response.payload[:push_rule]

    if @push_rule.valid?
      redirect_to admin_push_rule_path, notice: _('Push rule updated successfully.')
    else
      render :show
    end
  end

  private

  def check_push_rules_available!
    render_404 unless License.feature_available?(:push_rules)
  end

  def push_rule_params
    # filtering occurs in the PushRules::CreateOrUpdateService
    # where this method is passed into
    params.require(:organization_push_rule).to_unsafe_h
  end

  # rubocop: disable CodeReuse/ActiveRecord
  def set_push_rule
    @push_rule ||= OrganizationPushRule.find_or_initialize_by(organization_id: admin_current_organization.id)
  end
  # rubocop: enable CodeReuse/ActiveRecord

  def set_application_setting
    @application_setting = ApplicationSetting.current_without_cache
  end
end
