# frozen_string_literal: true

class Groups::HooksController < Groups::ApplicationController
  include ::WebHooks::HookActions

  # Authorize
  before_action :authorize_read_hook!, only: :index
  before_action :authorize_create_hook!, only: :create
  before_action :authorize_update_hook!, only: [:edit, :update]
  before_action :authorize_delete_hook!, only: :destroy
  before_action :authorize_test_hook!, only: :test
  before_action :check_group_webhooks_available!
  before_action :hook, only: [:edit, :update, :test, :destroy]
  before_action :set_feature_available, only: :index
  before_action :set_hide_search_settings
  before_action -> { check_rate_limit!(:web_hook_test, scope: { group: @group, user: current_user }) }, only: :test

  respond_to :html

  layout 'group_settings'

  urgency :low, [:test]

  def test
    result = TestHooks::GroupService.new(hook, current_user, permitted_params[:trigger]).execute

    if result.success?
      set_hook_execution_notice(result)
    else
      flash[:alert] = format(_('Hook execution failed. %{error}'), error: result.message)
    end

    redirect_back_or_default(default: { action: 'index' })
  end

  private

  def relation
    @group.hooks
  end

  def hook_container
    @group
  end

  def hook
    @hook ||= @group.hooks.find(permitted_params[:id])
  end

  def permitted_params
    params.permit(:id, :trigger)
  end

  def trigger_values
    GroupHook.triggers.values
  end

  def set_feature_available
    @feature_available = @group.licensed_feature_available?(:group_webhooks)
  end

  def set_hide_search_settings
    @hide_search_settings = true
  end

  def check_group_webhooks_available!
    render_404 unless @group.licensed_feature_available?(:group_webhooks) || helpers.show_promotions?(current_user)
  end

  def authorize_read_hook!
    render_404 unless can?(current_user, :read_webhook, group)
  end

  def authorize_create_hook!
    render_404 unless can?(current_user, :create_webhook, group)
  end

  def authorize_update_hook!
    render_404 unless can?(current_user, :update_webhook, group)
  end

  def authorize_delete_hook!
    render_404 unless can?(current_user, :delete_webhook, group)
  end

  def authorize_test_hook!
    render_404 unless can?(current_user, :test_webhook, group)
  end
end
