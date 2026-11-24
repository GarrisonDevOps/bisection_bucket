# frozen_string_literal: true

module Search
  module Zoekt
    # Settings module that contains Zoekt-specific settings configuration.
    # This module serves as a single source of truth for all Zoekt settings,
    # their types, defaults, and human-readable labels.
    #
    # Settings defined here are automatically:
    # - Added to visible attributes in ApplicationSettingsHelper
    # - Used to generate form inputs in the admin interface
    # - Displayed in the InfoService output
    #
    # To add a new setting:
    # 1. Add it to the SETTINGS hash with appropriate configuration
    # 2. The setting will automatically appear in all relevant places
    module Settings
      DEFAULT_INDEXING_TIMEOUT = '30m'
      DEFAULT_ROLLOUT_RETRY_INTERVAL = '1d'
      DEFAULT_LOST_NODE_THRESHOLD = '12h'
      DEFAULT_MAXIMUM_FILES = 500_000
      DEFAULT_FILE_SIZE_LIMIT = '1MB'
      DEFAULT_NUM_REPLICAS = 1
      DEFAULT_TRIGRAM_MAX = 20_000
      DEFAULT_FORCE_REINDEXING_PERCENTAGE = 0.25
      DEFAULT_MAX_PROJECTS_LEGACY_SEARCH = 1_000
      DEFAULT_MAX_RESTARTS_15M = 2
      DEFAULT_INITIAL_INDEXING_LIMIT = 1
      MAX_INITIAL_INDEXING_LIMIT = 100
      DISABLED_VALUE = '0'
      DURATION_BASE_REGEX = %r{([1-9]\d*)([mhd])}
      DURATION_INTERVAL_REGEX = %r{\A(?:0|#{DURATION_BASE_REGEX})\z}
      DURATION_INTERVAL_DISABLED_NOT_ALLOWED_REGEX = %r{\A#{DURATION_BASE_REGEX}\z}
      SIZE_REGEX = %r{\A([1-9]\d*)(B|KB|MB|GB|b|kb|mb|gb)\z}

      SETTINGS = {
        zoekt_indexing_enabled: {
          type: :boolean,
          default: false,
          label: -> { _('Enable indexing') }
        },
        zoekt_search_enabled: {
          type: :boolean,
          default: false,
          label: -> { _('Enable searching') }
        },
        zoekt_indexing_paused: {
          type: :boolean,
          default: false,
          label: -> { _('Pause indexing') }
        },
        zoekt_auto_index_root_namespace: {
          type: :boolean,
          default: false,
          label: -> { _('Index root namespaces automatically') }
        },
        zoekt_cache_response: {
          type: :boolean,
          default: true,
          label: -> {
            format(_("Cache search results for %{label}"), label: ::Search::Zoekt::Cache.humanize_expires_in)
          }
        },
        zoekt_cpu_to_tasks_ratio: {
          type: :float,
          default: 1.0,
          label: -> { _('Indexing CPU to tasks multiplier') },
          input_type: :number_field,
          input_options: { step: 0.1 }
        },
        zoekt_force_reindexing_percentage: {
          type: :float,
          default: DEFAULT_FORCE_REINDEXING_PERCENTAGE,
          label: -> { _('Probability of random force reindexing (percentage)') },
          input_type: :number_field,
          input_options: { step: 0.05, min: 0, max: 100 }
        },
        zoekt_indexing_parallelism: {
          type: :integer,
          default: 1,
          label: -> { _('Number of parallel processes per indexing task') },
          input_type: :number_field
        },
        zoekt_rollout_batch_size: {
          type: :integer,
          default: 32,
          label: -> { _('Number of namespaces per indexing rollout') },
          input_type: :number_field
        },
        zoekt_lost_node_threshold: {
          type: :text,
          default: DEFAULT_LOST_NODE_THRESHOLD,
          label: -> { _('Offline nodes automatically deleted after') },
          input_options: {
            placeholder: format(
              N_("Must be in the following format: `30m`, `2h`, or `1d`. Set to `%{val}` to disable."),
              val: DISABLED_VALUE
            )
          },
          input_type: :text_field
        },
        zoekt_indexing_timeout: {
          type: :text,
          default: DEFAULT_INDEXING_TIMEOUT,
          label: -> { _('Indexing timeout per project') },
          input_options: { placeholder: format(N_("Must be in the following format: `30m`, `2h`, or `1d`.")) },
          input_type: :text_field
        },
        zoekt_maximum_files: {
          type: :integer,
          default: DEFAULT_MAXIMUM_FILES,
          label: -> { _('Maximum number of files per project to be indexed') },
          input_type: :number_field
        },
        zoekt_indexed_file_size_limit: {
          type: :text,
          default: DEFAULT_FILE_SIZE_LIMIT,
          label: -> { _('Maximum file size for indexing') },
          input_options: {
            placeholder: format(
              N_('Must be in the following format: `5B`, `5b`, `1KB`, `1kb`, `2MB`, `2mb`, `1GB`, or `1gb`')
            )
          },
          input_type: :text_field
        },
        zoekt_trigram_max: {
          type: :integer,
          default: DEFAULT_TRIGRAM_MAX,
          label: -> { _('Maximum trigrams per file') },
          input_type: :number_field
        },
        zoekt_rollout_retry_interval: {
          type: :text,
          default: DEFAULT_ROLLOUT_RETRY_INTERVAL,
          label: -> { _('Retry interval for failed namespaces') },
          input_options: {
            placeholder: format(
              N_("Must be in the following format: `30m`, `2h`, or `1d`. Set to `%{val}` for no retries."),
              val: DISABLED_VALUE)
          },
          input_type: :text_field
        },
        zoekt_default_number_of_replicas: {
          type: :integer,
          default: DEFAULT_NUM_REPLICAS,
          label: -> { _('Number of replicas per namespace') },
          input_type: :number_field
        },
        zoekt_max_projects_for_legacy_search: {
          type: :integer,
          default: DEFAULT_MAX_PROJECTS_LEGACY_SEARCH,
          label: -> { _('Maximum number of projects for legacy search') },
          input_type: :number_field
        },
        zoekt_max_restarts_15m: {
          type: :integer,
          default: DEFAULT_MAX_RESTARTS_15M,
          label: -> { _('Maximum number of process restarts within 15 minutes for nodes') },
          input_type: :number_field,
          input_options: { min: 0 },
          admin_ui: -> { ::Search::Zoekt::ProcessHealth.active? }
        },
        zoekt_initial_indexing_limit: {
          type: :integer,
          default: DEFAULT_INITIAL_INDEXING_LIMIT,
          label: -> { _('Number of pending indices to start indexing per node') },
          input_type: :number_field,
          input_options: { min: 1, max: MAX_INITIAL_INDEXING_LIMIT },
          admin_ui: false
        }
      }.freeze

      FILTER_ADMIN_UI = ->(settings) do
        settings.reject do |_, config|
          value = config[:admin_ui]
          value = value.call if value.respond_to?(:call)
          value == false
        end
      end

      class << self
        def all_settings
          SETTINGS
        end

        def boolean_settings_ui
          FILTER_ADMIN_UI.call(SETTINGS.select { |_, config| config[:type] == :boolean })
        end

        def input_settings_ui
          input_types = %i[float integer text]
          FILTER_ADMIN_UI.call(SETTINGS.select { |_, config| input_types.include?(config[:type]) })
        end

        def indexing_timeout
          set_timeout = ApplicationSetting.current&.zoekt_indexing_timeout
          parse_duration(set_timeout, DEFAULT_INDEXING_TIMEOUT, allow_disabled: false)
        end

        def file_size_limit
          parse_size(ApplicationSetting.current&.zoekt_indexed_file_size_limit, DEFAULT_FILE_SIZE_LIMIT)
        end

        def rollout_retry_interval
          parse_duration(ApplicationSetting.current&.zoekt_rollout_retry_interval, DEFAULT_ROLLOUT_RETRY_INTERVAL)
        end

        def lost_node_threshold
          parse_duration(ApplicationSetting.current&.zoekt_lost_node_threshold, DEFAULT_LOST_NODE_THRESHOLD)
        end

        def default_number_of_replicas
          ApplicationSetting.current&.zoekt_default_number_of_replicas || 1
        end

        def force_reindexing_percentage
          ApplicationSetting.current&.zoekt_force_reindexing_percentage || DEFAULT_FORCE_REINDEXING_PERCENTAGE
        end

        def max_projects_for_legacy_search
          ApplicationSetting.current&.zoekt_max_projects_for_legacy_search || DEFAULT_MAX_PROJECTS_LEGACY_SEARCH
        end

        def max_restarts_15m
          ApplicationSetting.current&.zoekt_max_restarts_15m || DEFAULT_MAX_RESTARTS_15M
        end

        def initial_indexing_limit
          ApplicationSetting.current&.zoekt_initial_indexing_limit || DEFAULT_INITIAL_INDEXING_LIMIT
        end

        private

        def parse_duration(setting_value, default_value, allow_disabled: true)
          return if setting_value.blank?
          return if setting_value == DISABLED_VALUE && allow_disabled

          regex = allow_disabled ? DURATION_INTERVAL_REGEX : DURATION_INTERVAL_DISABLED_NOT_ALLOWED_REGEX
          match = setting_value.match(regex)
          match ||= default_value.match(regex)

          value = match[1].to_i
          unit = match[2]
          case unit
          when 'm' then value.minute
          when 'h' then value.hour
          else value.day # unit can only be one of these [m h d] due to DURATION_BASE_REGEX match
          end
        end

        def parse_size(setting_value, default_value)
          match = setting_value&.match(SIZE_REGEX)
          match ||= default_value.match(SIZE_REGEX)
          value = match[1].to_i
          unit = match[2]
          case unit.downcase
          when 'b' then value.bytes
          when 'kb' then value.kilobytes
          when 'mb' then value.megabytes
          else value.gigabytes # unit.downcase can only be one of these [b kb mb gb] due to SIZE_REGEX match
          end
        end
      end
    end
  end
end
