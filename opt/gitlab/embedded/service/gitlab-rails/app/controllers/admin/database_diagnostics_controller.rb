# frozen_string_literal: true

module Admin
  class DatabaseDiagnosticsController < Admin::ApplicationController
    include Gitlab::InternalEventsTracking

    feature_category :database
    authorize! :read_admin_database_diagnostics,
      only: %i[index run_collation_check collation_check_results run_schema_check schema_check_results
        run_lfk_backlog_check lfk_backlog_check_results active_session_history active_session_history_queries
        active_session_history_timeline]

    urgency :low, %i[active_session_history active_session_history_queries active_session_history_timeline]

    WAIT_EVENT_TYPE_MAX_LENGTH = 64

    WORKER_CONFIGS = {
      collation: {
        worker: ::Database::CollationCheckerWorker,
        cache_key: ::Database::CollationCheckerWorker::COLLATION_CHECK_CACHE_KEY
      },
      schema: {
        worker: ::Database::SchemaCheckerWorker,
        cache_key: ::Database::SchemaCheckerWorker::SCHEMA_CHECK_CACHE_KEY
      },
      lfk_backlog: {
        worker: ::Database::LooseForeignKeysBacklogCheckerWorker,
        cache_key: ::Database::LooseForeignKeysBacklogCheckerWorker::BACKLOG_CHECK_CACHE_KEY
      }
    }.freeze

    def index
      @database_information = ::Gitlab::Database::DatabaseInformation.execute

      track_internal_event('visit_db_diagnostics_page', user: current_user)
    end

    def run_collation_check
      run_check(:collation)
    end

    def run_schema_check
      run_check(:schema)
    end

    def collation_check_results
      check_results(:collation)
    end

    def schema_check_results
      check_results(:schema)
    end

    def run_lfk_backlog_check
      run_check(:lfk_backlog)
    end

    def lfk_backlog_check_results
      check_results(:lfk_backlog)
    end

    def active_session_history
      render_active_session_history(::Gitlab::Database::PgAsh::Report::OVERVIEW) do |report|
        { sampling_enabled: Gitlab::CurrentSettings.pg_ash_sampling_enabled, **report.overview }
      end
    end

    def active_session_history_queries
      wait_event_type = active_session_history_params[:wait_event_type]
      return render_invalid_wait_event_type unless valid_wait_event_type?(wait_event_type)

      render_active_session_history(::Gitlab::Database::PgAsh::Report::DRILL_DOWN) do |report|
        { queries_available: true, queries: report.queries(wait_event_type: wait_event_type) }
      rescue ::Gitlab::Database::PgAsh::Report::QueryDetailsUnavailableError
        { queries_available: false, queries: [] }
      end
    end

    def active_session_history_timeline
      wait_event_types = active_session_history_params[:wait_event_types]
      return render_invalid_wait_event_type unless valid_wait_event_types?(wait_event_types)

      render_active_session_history(::Gitlab::Database::PgAsh::Report::OVERVIEW) do |report|
        { timelines: report.timelines(wait_event_types: wait_event_types.uniq) }
      end
    end

    private

    def valid_wait_event_type?(wait_event_type)
      wait_event_type.is_a?(String) && wait_event_type.present? &&
        wait_event_type.length <= WAIT_EVENT_TYPE_MAX_LENGTH
    end

    # Up to as many as the overview lists.
    def valid_wait_event_types?(wait_event_types)
      wait_event_types.is_a?(Array) &&
        wait_event_types.size.between?(1, ::Gitlab::Database::PgAsh::Report::WAIT_EVENT_TYPE_LIMIT) &&
        wait_event_types.all? { |wait_event_type| valid_wait_event_type?(wait_event_type) }
    end

    def render_invalid_wait_event_type
      render json: { error: s_('DatabaseDiagnostics|Invalid wait event type') }, status: :bad_request
    end

    # Every response echoes its window, so the page can pin follow-up reads
    # to the same minutes after now has moved on.
    def render_active_session_history(window_kind)
      version = ::Gitlab::Database::PgAsh::Installer.new.installed_version
      return render json: { installed: false } unless version
      return render_unsupported_pg_ash(version) unless version == ::Gitlab::Database::PgAsh::VENDORED_VERSION

      # Only the overview ends at the newest rollup. The drill-down reads raw samples,
      # which are newer, but its 30 days count back from the rollup too.
      overview = window_kind == ::Gitlab::Database::PgAsh::Report::OVERVIEW
      newest_rollup = ::Gitlab::Database::PgAsh::Report.rollup_watermark
      window = ::Gitlab::Database::PgAsh::Report.window(
        window_kind,
        from: active_session_history_params[:from],
        to: active_session_history_params[:to],
        latest_end: (newest_rollup if overview),
        newest_rollup: newest_rollup
      )

      report = ::Gitlab::Database::PgAsh::Report.new(window)

      render json: {
        installed: true,
        window: { from: window.begin.utc.iso8601, to: window.end.utc.iso8601 },
        **yield(report)
      }
    rescue ::Gitlab::Database::PgAsh::Report::InvalidWindowError
      render json: { error: s_('DatabaseDiagnostics|Invalid window') }, status: :bad_request
    rescue ActiveRecord::StatementInvalid => e
      active_session_history_error(e)
    end

    def active_session_history_params
      params.permit(:from, :to, :wait_event_type, wait_event_types: [])
    end

    # The reads call functions of the vendored version, which another version may not have.
    def render_unsupported_pg_ash(version)
      render json: {
        installed: true,
        supported: false,
        installed_version: version,
        supported_version: ::Gitlab::Database::PgAsh::VENDORED_VERSION
      }
    end

    # Database errors can carry SQL and internal detail, so only a generic
    # message reaches the browser.
    def active_session_history_error(exception)
      Gitlab::ErrorTracking.track_exception(
        exception,
        action: action_name,
        wait_event_type: active_session_history_params[:wait_event_type],
        wait_event_types: active_session_history_params[:wait_event_types]
      )

      render json: { error: s_('DatabaseDiagnostics|Failed to read active session history') },
        status: :internal_server_error
    end

    def run_check(check_type)
      worker_class = WORKER_CONFIGS[check_type][:worker]
      job_id = worker_class.perform_async

      if job_id
        render json: { status: 'scheduled', job_id: job_id }
      else
        render json: { error: 'Failed to schedule job' }, status: :internal_server_error
      end
    end

    def check_results(check_type)
      cache_key = WORKER_CONFIGS[check_type][:cache_key]
      results_json = Rails.cache.read(cache_key)

      if results_json.present?
        results = Gitlab::Json.safe_parse(results_json)
        render json: results
      else
        render json: { error: 'No results available yet' }, status: :not_found
      end
    end
  end
end
