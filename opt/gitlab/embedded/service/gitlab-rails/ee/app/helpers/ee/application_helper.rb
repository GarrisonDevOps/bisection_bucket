# frozen_string_literal: true

module EE
  module ApplicationHelper
    extend ::Gitlab::Utils::Override
    include ::Gitlab::Utils::StrongMemoize
    include ::SecretsManagement::EnrollmentHelper

    DB_LAG_SHOW_THRESHOLD = 60 # seconds
    LOG_CURSOR_CHECK_TIME = ::Gitlab::Geo::LogCursor::Daemon::SECONDARY_CHECK_INTERVAL
    EVENT_PROCESSING_TIME = 60.seconds
    EVENT_LAG_SHOW_THRESHOLD = DB_LAG_SHOW_THRESHOLD.seconds + LOG_CURSOR_CHECK_TIME + EVENT_PROCESSING_TIME

    override :read_only_message
    def read_only_message
      return ::Gitlab::MaintenanceModeHelper.maintenance_mode_message if ::Gitlab.maintenance_mode?

      super unless ::Gitlab::Geo.secondary?
    end

    def read_only_description
      _('You are on a read-only GitLab instance.') if ::Gitlab.maintenance_mode? && !::Gitlab::Geo.secondary?
    end

    def geo_secondary_read_only_description
      return unless ::Gitlab::Geo.secondary?

      message = @limited_actions_message ? s_('Geo|You may be able to make a limited amount of changes or perform a limited amount of actions on this page.') : s_('Geo|If you want to make changes, you must visit the primary site.')

      message = "#{message} #{lag_message}".html_safe if lag_message

      tag.span do
        concat(safe_format(s_('Geo|You are on a secondary, %{b_open}read-only%{b_close} Geo site.'), tag_pair(tag.b, :b_open, :b_close)))
        concat(" #{message}")
      end
    end

    def lag_message
      if !db_lag.nil? && db_lag > DB_LAG_SHOW_THRESHOLD
        return format(s_('Geo|The database is currently %{db_lag} behind the primary site.'), db_lag: time_ago_in_words(db_lag.seconds.ago)).html_safe
      end

      if unprocessed_too_old?
        minutes_behind = time_ago_in_words(next_unprocessed_event.created_at)
        format(s_('Geo|The site is currently %{minutes_behind} behind the primary site.'), minutes_behind: minutes_behind).html_safe
      end
    end

    def show_geo_misconfigured_banner?
      current_user&.can_admin_all_resources? && ::Gitlab::Geo.current_node_misconfigured?
    end

    def geo_configured_node_name
      ::GeoNode.current_node_name
    end

    def render_ce(partial, locals = {})
      render template: find_ce_template(partial), locals: locals
    end

    # Tries to find a matching partial first, if there is none, we try to find a matching view
    # rubocop: disable CodeReuse/ActiveRecord
    def find_ce_template(name)
      prefixes = [] # So don't create extra [] garbage

      if ce_lookup_context.exists?(name, prefixes, true)
        ce_lookup_context.find(name, prefixes, true)
      else
        ce_lookup_context.find(name, prefixes, false)
      end
    end
    # rubocop: enable CodeReuse/ActiveRecord

    def ce_lookup_context
      @ce_lookup_context ||= begin
        ee_path_regex = %r{\A#{Regexp.escape(Rails.root.to_s)}/(?:domains/[^/]+/)?ee/}

        ce_view_paths = lookup_context.view_paths.paths.reject do |resolver|
          resolver.to_path.match?(ee_path_regex)
        end

        ActionView::LookupContext.new(ce_view_paths)
      end
    end

    override :autocomplete_data_sources
    def autocomplete_data_sources(object, noteable_type)
      return {} unless object && noteable_type

      object.is_a?(Group) ? group_autocomplete_data_sources(object).merge(super) : project_autocomplete_data_sources(object).merge(super)
    end

    def group_autocomplete_data_sources(object)
      enabled_for_vulnerabilities = object.feature_available?(:security_dashboard)
      {
        epics: epics_group_autocomplete_sources_path(object),
        iterations: object.feature_available?(:iterations) ? iterations_group_autocomplete_sources_path(object) : nil,
        vulnerabilities: enabled_for_vulnerabilities ? vulnerabilities_group_autocomplete_sources_path(object) : nil,
        wikis: object.feature_available?(:wiki, current_user) ? wikis_group_autocomplete_sources_path(object) : nil
      }.compact
    end

    def project_autocomplete_data_sources(object)
      enabled_for_vulnerabilities = object.feature_available?(:security_dashboard)
      {
        epics: object.group&.feature_available?(:epics) ? epics_project_autocomplete_sources_path(object) : nil,
        iterations: object.group&.feature_available?(:iterations) ? iterations_project_autocomplete_sources_path(object) : nil,
        vulnerabilities: enabled_for_vulnerabilities ? vulnerabilities_project_autocomplete_sources_path(object) : nil
      }.compact
    end

    override :show_last_push_widget?
    def show_last_push_widget?(event)
      show = super
      project = event.project

      # Skip if this was a mirror update
      return false if project.mirror? && project.repository.up_to_date_with_upstream?(event.branch_name)

      show
    end

    override :page_class
    def page_class
      class_names = super
      class_names << 'with-bloom' if show_ai_bloom?
      # Reserve the AI navigation rail width server-side to avoid a layout
      # shift when the Vue-rendered panel mounts.
      class_names << 'page-with-ai-panel' if show_ai_panel?
      class_names
    end

    private

    # Gates the bloom background so it only renders on pages that surface
    # AI features.
    def show_ai_bloom?
      ai_panel_renders?
    end
    strong_memoize_attr :show_ai_bloom?

    def show_ai_panel?
      ai_panel_renders?
    end
    strong_memoize_attr :show_ai_panel?

    def ai_panel_renders?
      ::DuoChatPanel::Component.new(
        user: current_user,
        project: @project,
        group: @group,
        controller_name: controller_name
      ).render?
    end
    strong_memoize_attr :ai_panel_renders?

    def db_lag
      return unless ::Gitlab::Geo::HealthCheck.new.replication_enabled?

      @db_lag ||= Rails.cache.fetch('geo:db_lag', expires_in: 20.seconds) do
        ::Gitlab::Geo::HealthCheck.new.db_replication_lag_seconds
      end
    end

    def next_unprocessed_event
      @next_unprocessed_event ||= ::Geo::EventLog.next_unprocessed_event
    end

    def unprocessed_too_old?
      Rails.cache.fetch('geo:unprocessed_too_old', expires_in: 20.seconds) do
        break false unless next_unprocessed_event

        next_unprocessed_event.created_at < EVENT_LAG_SHOW_THRESHOLD.ago
      end
    end
  end
end
