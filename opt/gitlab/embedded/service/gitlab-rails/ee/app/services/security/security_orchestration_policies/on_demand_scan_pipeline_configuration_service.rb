# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class OnDemandScanPipelineConfigurationService
      include Gitlab::Utils::StrongMemoize
      include CiConfigurationMetadata

      def initialize(project)
        @project = project
      end

      def execute(actions)
        actions.map.with_index { |action, index| prepare_policy_configuration(action, index) }
      end

      private

      TEMPLATES = {
        scan: 'DAST-On-Demand-Scan',
        api: 'DAST-On-Demand-API-Scan'
      }.freeze

      attr_reader :project

      def prepare_policy_configuration(action, index)
        {
          "dast-on-demand-#{index}" => prepare_on_demand_scan_configuration(action)
        }.deep_symbolize_keys
      end

      def prepare_on_demand_scan_configuration(action)
        site_profile = dast_site_profile(action[:site_profile])
        scanner_profile = dast_scanner_profile(action[:scanner_profile])

        result = prepare_base_configuration(site_profile, scanner_profile)
        return error_script(result.message, action) unless result.success?

        action_variables = action[:variables].to_h.stringify_keys
        ci_configuration = YAML.safe_load(result.payload[:ci_configuration])
        template = site_profile.api? ? dast_on_demand_api_template : dast_on_demand_template

        template[:dast]
          .merge(action[:tags] ? { tags: action[:tags] } : {})
          .merge(ignore_default_before_after_script?(action) ? { before_script: [], after_script: [] } : {})
          .deep_merge(
            {
              'stage' => 'dast',
              'variables' => dast_on_demand_variables(template, action_variables),
              'dast_configuration' => ci_configuration['dast']['dast_configuration']
            }.compact
          ).tap { |config| merge_configuration_metadata!(config, action[:metadata]) }
      end

      def dast_site_profile(site_profile_name)
        DastSiteProfilesFinder.new(project_id: project.id, name: site_profile_name).execute.first
      end

      def dast_scanner_profile(scanner_profile_name)
        return if scanner_profile_name.blank?

        DastScannerProfilesFinder.new(project_ids: [project.id], name: scanner_profile_name).execute.first
      end

      def prepare_base_configuration(site_profile, scanner_profile)
        AppSec::Dast::ScanConfigs::BuildService
          .new(container: project, params: { dast_site_profile: site_profile, dast_scanner_profile: scanner_profile })
          .execute
      end

      def ignore_default_before_after_script?(action)
        action.dig(:scan_settings, :ignore_default_before_after_script)
      end

      def dast_on_demand_template
        fetch_dast_on_demand_template(:scan)
      end
      strong_memoize_attr :dast_on_demand_template

      def dast_on_demand_api_template
        fetch_dast_on_demand_template(:api)
      end
      strong_memoize_attr :dast_on_demand_api_template

      def fetch_dast_on_demand_template(scan_type)
        template = ::TemplateFinder.build(:gitlab_ci_ymls, nil, name: TEMPLATES[scan_type]).execute
        ci_yaml = Gitlab::Ci::Config::Yaml::Loader.new(template.content).load

        ci_yaml.content
      end

      def dast_on_demand_variables(template, action_variables)
        template[:variables]
          .merge(template.dig(:dast, :variables).to_h)
          .merge(action_variables)
      end

      def error_script(error_message, action)
        {
          'script' => "echo \"Error during On-Demand Scan execution: #{error_message}\" && false",
          'allow_failure' => true
        }.tap { |config| merge_configuration_metadata!(config, action[:metadata]) }
      end
    end
  end
end
