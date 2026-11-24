# frozen_string_literal: true

module Analytics
  module CustomDashboards
    class SystemDashboardsLoader
      include SchemaValidator

      PATH = Rails.root.join('ee/lib/gitlab/analytics/dashboards/system')
      SCHEMA_PATH = 'ee/app/validators/json_schemas/analytics_dashboard.json'

      def self.all
        return new.all if reload_on_every_call?

        @all ||= new.all
      end

      def self.find_by_slug(slug)
        by_slug[slug]
      end

      def self.by_slug
        return all.index_by(&:slug) if reload_on_every_call?

        @by_slug ||= all.index_by(&:slug)
      end

      # The dashboard YAML lives outside any autoload path, so nothing invalidates the
      # memoized copy when it changes. Re-reading in development means an edit shows up on
      # the next request instead of after a Puma restart.
      def self.reload_on_every_call?
        Rails.env.development?
      end
      private_class_method :reload_on_every_call?

      def all
        Dir.glob(PATH.join('*.yaml')).filter_map do |file|
          load_dashboard(file)
        end
      end

      private

      def load_dashboard(file)
        config = load_yaml(file)
        return unless config

        SystemDashboard.new(slug: File.basename(file, '.yaml'), config: config, errors: schema_errors(file, config))
      end

      # A file that does not parse, or parses to something other than a mapping, raises here
      # and is dropped: there is no dashboard to show the error on.
      def load_yaml(file)
        Gitlab::Config::Loader::Yaml.new(File.read(file)).load_raw!
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, file: File.basename(file))
        nil
      end

      # Kept rather than dropped: the dashboard page shows these to its author.
      def schema_errors(file, config)
        # A panel is a oneOf, so one typo is reported once per branch; the alert keys on the message.
        errors = (schema_errors_for(config) || []).uniq
        return errors if errors.empty?

        Gitlab::ErrorTracking.track_exception(
          StandardError.new("Invalid system dashboard YAML: #{errors.join(', ')}"),
          file: File.basename(file)
        )
        errors
      end
    end
  end
end
