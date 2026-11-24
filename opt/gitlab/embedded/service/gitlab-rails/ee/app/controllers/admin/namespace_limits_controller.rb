# frozen_string_literal: true

module Admin
  class NamespaceLimitsController < Admin::ApplicationController
    feature_category :consumables_cost_management
    urgency :low

    before_action :verify_limits_available!

    def index; end

    def export_usage
      # rubocop:disable CodeReuse/Worker
      Namespaces::StorageUsageExportWorker.perform_async('free', current_user.id)
      # rubocop:enable CodeReuse/Worker

      flash[:notice] = _('CSV is being generated and will be emailed to you upon completion.')

      redirect_to admin_namespace_limits_path
    end

    private

    def verify_limits_available!
      not_found unless ::Gitlab::Saas.feature_available?(:namespaces_storage_limit)
    end
  end
end
