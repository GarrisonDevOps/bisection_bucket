# frozen_string_literal: true

module Admin
  class DatabasePreUpgradeChecksController < Admin::ApplicationController
    include Gitlab::InternalEventsTracking

    feature_category :database
    authorize! :read_admin_database_diagnostics, only: %i[index]

    def index
      @search_path_information = ::Gitlab::Database::SearchPathInformation.execute

      track_internal_event('visit_db_pre_upgrade_checks_page', user: current_user)
    end
  end
end
