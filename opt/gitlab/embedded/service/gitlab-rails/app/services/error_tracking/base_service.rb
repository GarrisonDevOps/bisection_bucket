# frozen_string_literal: true

module ErrorTracking
  class BaseService < ::BaseProjectService
    include Gitlab::Utils::UsageData

    SENTRY_ISSUE_ID_REGEX = /\A\d+\z/
    SENTRY_CACHE_ENTRY_LIMIT_ERROR_TYPE = 'sentry_cache_entry_limit_reached'

    def initialize(project, user = nil, params = {})
      super(project: project, current_user: user, params: params.dup)
    end

    def execute
      return unauthorized if unauthorized

      perform
    end

    private

    def perform
      raise NotImplementedError, "#{self.class} does not implement #{__method__}"
    end

    def compose_response(response, &block)
      errors = parse_errors(response)
      return errors if errors

      yield if block

      track_usage_event(params[:tracking_event], current_user.id) if params[:tracking_event]

      success(parse_response(response))
    end

    def parse_response(response)
      raise NotImplementedError, "#{self.class} does not implement #{__method__}"
    end

    def unauthorized
      return error('Error Tracking is not enabled') unless enabled?

      error('Access denied', :unauthorized) unless can_read?
    end

    def parse_errors(response)
      return error('Not ready. Try again later', :no_content) unless response

      error(response[:error], http_status_for(response[:error_type])) if response[:error].present?
    end

    def invalid_param_error(param)
      error("Bad Request: Invalid #{param}", :bad_request)
    end

    def sentry_backend?
      !project_error_tracking_setting.integrated_client?
    end

    def valid_sentry_issue_id?
      SENTRY_ISSUE_ID_REGEX.match?(params[:issue_id].to_s)
    end

    # Each distinct Sentry request is its own reactive cache entry and refresh job, so only
    # cache misses count; polling an existing entry is free. The per-user check runs first
    # and short-circuits, so a blocked user stops consuming the project budget.
    def sentry_cache_entry_limited?(request, opts)
      return false if project_error_tracking_setting.sentry_cache_alive?(request, opts)

      ::Gitlab::ApplicationRateLimiter.throttled?(
        :error_tracking_sentry_cache_entries_per_user, scope: { user: current_user, project: project }
      ) || ::Gitlab::ApplicationRateLimiter.throttled?(
        :error_tracking_sentry_cache_entries_per_project, scope: { project: project }
      )
    end

    def sentry_cache_entry_limit_error
      {
        error: ::Gitlab::ApplicationRateLimiter.throttled_error_message,
        error_type: SENTRY_CACHE_ENTRY_LIMIT_ERROR_TYPE
      }
    end

    def http_status_for(error_type)
      case error_type
      when ErrorTracking::ProjectErrorTrackingSetting::SENTRY_API_ERROR_TYPE_MISSING_KEYS
        :internal_server_error
      when SENTRY_CACHE_ENTRY_LIMIT_ERROR_TYPE
        :too_many_requests
      else
        :bad_request
      end
    end

    def project_error_tracking_setting
      project.error_tracking_setting
    end

    def enabled?
      project_error_tracking_setting&.enabled?
    end

    def can_read?
      can?(current_user, :read_sentry_issue, project)
    end

    def can_update?
      can?(current_user, :update_sentry_issue, project)
    end

    def error_repository
      Gitlab::ErrorTracking::ErrorRepository.build(project)
    end

    def handle_error_repository_exceptions
      yield
    rescue Gitlab::ErrorTracking::ErrorRepository::DatabaseError => e
      { error: e.message }
    end
  end
end
