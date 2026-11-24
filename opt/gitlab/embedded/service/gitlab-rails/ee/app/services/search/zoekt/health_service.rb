# frozen_string_literal: true

module Search
  module Zoekt
    class HealthService
      def self.execute(...)
        new(...).execute
      end

      def initialize(logger:, options: {})
        @logger = logger
        @options = options
      end

      def execute
        logger.info(Rainbow("=== Zoekt Health Check ===").bright.cyan)

        node_result = HealthCheck::NodeStatusService.execute(logger: logger)
        configuration_result = HealthCheck::ConfigurationService.execute(logger: logger)
        connectivity_result = HealthCheck::ConnectivityService.execute(logger: logger)
        process_health_result = HealthCheck::ProcessHealthService.execute(logger: logger)

        logger.info("")

        # Display overall status with appropriate color
        all_results = [node_result, configuration_result, connectivity_result, process_health_result]
        status = determine_overall_status(all_results)
        status_color = status_color_for(status)

        logger.info("#{Rainbow('Overall Status:').bright.yellow} #{Rainbow(status.to_s.upcase).color(status_color)}")

        # Display recommendations if there are any issues
        display_recommendations(all_results)

        exit_code = exit_code(status)
        should_exit = exit_code > 0 && !options.key?(:watch_mode)
        exit(exit_code) if should_exit

        exit_code
      end

      private

      attr_reader :logger, :options

      def determine_overall_status(results)
        return :unhealthy if results.any? { |result| result[:status] == :unhealthy }
        return :degraded if results.any? { |result| result[:status] == :degraded }

        :healthy
      end

      def status_color_for(status)
        case status
        when :healthy
          :green
        when :degraded
          :yellow
        when :unhealthy
          :red
        else
          :white
        end
      end

      def display_recommendations(results)
        all_errors = results.flat_map { |result| result[:errors] }
        all_warnings = results.flat_map { |result| result[:warnings] }

        return if all_errors.empty? && all_warnings.empty?

        logger.info("")
        logger.info(Rainbow("Recommendations:").bright.yellow)

        all_errors.each do |error|
          logger.info("  #{Rainbow('•').red} #{error}")
        end

        all_warnings.each do |warning|
          logger.info("  #{Rainbow('•').yellow} #{warning}")
        end
      end

      def exit_code(status)
        case status
        when :healthy then 0
        when :degraded then 1
        else 2
        end
      end
    end
  end
end
