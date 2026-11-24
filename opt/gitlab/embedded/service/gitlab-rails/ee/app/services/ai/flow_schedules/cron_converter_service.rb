# frozen_string_literal: true

module Ai
  module FlowSchedules
    # Converts a user-friendly schedule configuration (from the frontend)
    # into a standard cron expression + timezone.
    #
    # Frontend submits schedule config in the flow trigger's filter JSON:
    #   { "scheduled" => { "frequency" => "DAILY", "minute" => 30, "hour" => 14, "timezone" => "America/New_York" } }
    #
    # This service converts it to:
    #   { cron: "30 14 * * *", cron_timezone: "America/New_York" }
    class CronConverterService
      FREQUENCIES = {
        'EVERY_15_MINUTES' => ->(_config) { '*/15 * * * *' },
        'EVERY_30_MINUTES' => ->(_config) { '*/30 * * * *' },
        'HOURLY' => ->(config) { "#{config['minute'] || 0} * * * *" },
        'DAILY' => ->(config) { "#{config['minute'] || 0} #{config['hour'] || 0} * * *" },
        'WEEKDAYS' => ->(config) { "#{config['minute'] || 0} #{config['hour'] || 0} * * 1-5" },
        'WEEKLY' => ->(config) {
          "#{config['minute'] || 0} #{config['hour'] || 0} * * #{config['dayOfWeek'] || 0}"
        },
        'MONTHLY' => ->(config) {
          "#{config['minute'] || 0} #{config['hour'] || 0} #{config['dayOfMonth'] || 1} * *"
        }
      }.freeze

      DEFAULT_TIMEZONE = 'Etc/UTC'

      def initialize(schedule_config)
        @config = schedule_config&.stringify_keys || {}
      end

      def execute
        frequency = @config['frequency']
        converter = FREQUENCIES[frequency]

        unless converter
          return ServiceResponse.error(
            message: "Unknown schedule frequency: #{frequency}. " \
              "Valid values: #{FREQUENCIES.keys.join(', ')}"
          )
        end

        cron = converter.call(@config)
        cron_timezone = @config['timezone'].presence || DEFAULT_TIMEZONE

        # Validate the generated cron
        parser = Gitlab::Ci::CronParser.new(cron, cron_timezone)
        return ServiceResponse.error(message: "Generated invalid cron expression: #{cron}") unless parser.cron_valid?

        return ServiceResponse.error(message: "Invalid timezone: #{cron_timezone}") unless parser.cron_timezone_valid?

        ServiceResponse.success(payload: { cron: cron, cron_timezone: cron_timezone })
      end
    end
  end
end
