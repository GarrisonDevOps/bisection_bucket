# frozen_string_literal: true

module CloudConnector
  class SyncServiceTokenWorker
    include ApplicationWorker

    data_consistency :sticky

    include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- Does not perform work scoped to a context

    idempotent!

    sidekiq_options retry: 3

    worker_has_external_dependencies!

    feature_category :system_access

    def perform(params = {})
      # We only refresh the token if we force a refresh, have no token or the token expires soon.
      access_token = ::CloudConnector::ServiceAccessToken.last
      unless params['force'] || access_token.nil? || access_token.refresh_required?
        log_extra_metadata_on_done(:result, 'skipping token refresh')
        return
      end

      # Passing the license ID is necessary in cases where the license was just updated, so the
      # worker may be reading a stale cache: https://gitlab.com/gitlab-org/gitlab/-/issues/498456
      # When running as a cron job, we always use the current license.
      license = License.find_by_id(params['license_id']) || License.current
      result = ::CloudConnector::SyncCloudConnectorAccessService.new(license).execute

      log_extra_metadata_on_done(:error_message, result[:message]) unless result.success?
    end
  end
end
