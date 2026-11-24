# frozen_string_literal: true

module Search
  module Zoekt
    module HealthCheck
      class ConfigurationService
        include StatusReporting

        def self.execute(...)
          new(...).execute
        end

        def initialize(logger:)
          @logger = logger
          @status = :healthy
          @warnings = []
          @errors = []
        end

        def execute
          logger.info("")
          logger.info(Rainbow("Configuration:").bright.yellow)

          check_indexing_enabled
          check_namespace_indexing_status

          {
            status: @status,
            warnings: @warnings,
            errors: @errors
          }
        end

        private

        def check_indexing_enabled
          setting = ApplicationSetting.current

          if setting.zoekt_indexing_enabled?
            log_check("✓ Indexing enabled", :green)
          else
            add_error("Enable indexing in Admin > Settings > Search > Exact code search")
            log_check("✗ Indexing disabled", :red)
          end

          if setting.zoekt_search_enabled?
            log_check("✓ Searching enabled", :green)
          else
            add_warning("Enable searching in Admin > Settings > Search > Exact code search")
            log_check("⚠ Searching disabled", :yellow)
          end

          if setting.zoekt_indexing_paused?
            add_warning("Unpause indexing in Admin > Settings > Search > Exact code search")
            log_check("⚠ Indexing paused", :yellow)
          else
            log_check("✓ Indexing active", :green)
          end
        end

        def check_namespace_indexing_status
          total_namespaces = Search::Zoekt::EnabledNamespace.count
          with_missing_indices = Search::Zoekt::EnabledNamespace.with_missing_indices.count
          with_search_disabled = Search::Zoekt::EnabledNamespace.search_disabled.count

          if total_namespaces == 0
            add_warning("Enable namespaces for indexing or set auto-index root namespaces in Admin settings")
            log_check("⚠ 0 namespaces enabled for indexing", :yellow)
            return
          end

          log_check("✓ #{total_namespaces} namespaces enabled for indexing", :green)

          if with_missing_indices > 0
            add_warning(
              "Wait for indexing to complete or check for indexing errors on #{with_missing_indices} namespaces"
            )
            log_check("⚠ #{with_missing_indices} namespaces without indices", :yellow)
          else
            log_check("✓ All namespaces have indices", :green)
          end

          if with_search_disabled > 0
            add_warning("Enable search on #{with_search_disabled} namespaces in group settings")
            log_check("⚠ #{with_search_disabled} namespaces with search disabled", :yellow)
          else
            log_check("✓ All namespaces have search enabled", :green)
          end

          # Check repository indexing status
          total_repositories = Search::Zoekt::Repository.count
          ready_repositories = Search::Zoekt::Repository.ready.count

          return unless total_repositories > 0

          ready_percentage = (ready_repositories.to_f / total_repositories * 100).round(1)
          if ready_percentage < 50
            add_error("Check indexing logs and resolve errors - only #{ready_percentage}% repositories indexed")
            log_check("✗ #{ready_repositories}/#{total_repositories} repositories ready (#{ready_percentage}%)", :red)
          elsif ready_percentage < 80
            add_warning("Wait for indexing completion - #{ready_percentage}% repositories indexed")
            log_check("⚠ #{ready_repositories}/#{total_repositories} repositories ready (#{ready_percentage}%)",
              :yellow)
          else
            log_check("✓ #{ready_repositories}/#{total_repositories} repositories ready (#{ready_percentage}%)",
              :green)
          end
        end
      end
    end
  end
end
