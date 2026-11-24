# frozen_string_literal: true

module Security
  module ScanCoverageBanners
    class GenerateContentService
      ROLLOUT_THRESHOLD = 0.25

      SCANNER_NAMES = {
        sast: 'application security testing',
        secret_detection: 'secret detection'
      }.freeze

      def initialize(group)
        @group = group
      end

      def execute
        return ServiceResponse.success(payload: nil) if total_projects_count == 0
        return ServiceResponse.success(payload: nil) if threshold_met?

        ServiceResponse.success(payload: {
          variant: variant,
          title: title,
          message: message,
          cta_text: cta_text,
          cta_url: cta_url,
          banner_type: banner_type
        })
      end

      private

      attr_reader :group

      def total_projects_count
        @total_projects_count ||= group.all_unarchived_project_ids.size
      end

      def sast_status
        @sast_status ||= ::Security::AnalyzerNamespaceStatus.status_for(group, :sast)
      end

      def secret_detection_status
        @secret_detection_status ||= ::Security::AnalyzerNamespaceStatus.status_for(group, :secret_detection)
      end

      def configured_count(status)
        return 0 unless status

        status.success + status.failure + status.stale
      end

      def sast_count
        @sast_count ||= configured_count(sast_status)
      end

      def secret_detection_count
        @secret_detection_count ||= configured_count(secret_detection_status)
      end

      def sast_configured?
        sast_count > 0
      end

      def secret_detection_configured?
        secret_detection_count > 0
      end

      def configured_scanner_count
        [sast_configured?, secret_detection_configured?].count(true)
      end

      def count_for(type)
        [raw_count_for(type), total_projects_count].min
      end

      def raw_count_for(type)
        type == :sast ? sast_count : secret_detection_count
      end

      def fraction_for(type)
        count_for(type).to_f / total_projects_count
      end

      def above_threshold?(type)
        fraction_for(type) >= ROLLOUT_THRESHOLD
      end

      def threshold_met?
        sast_configured? && secret_detection_configured? &&
          (above_threshold?(:sast) || above_threshold?(:secret_detection))
      end

      def no_scanners_configured?
        configured_scanner_count == 0
      end

      def two_scanners_configured?
        configured_scanner_count == 2
      end

      def variant
        no_scanners_configured? ? 'warning' : 'tip'
      end

      def configured_scanner_type
        sast_configured? ? :sast : :secret_detection
      end

      def scanner_label(type)
        SCANNER_NAMES.fetch(type)
      end

      def scanner_label_capitalized(type)
        scanner_label(type).capitalize
      end

      def delimited(count)
        ActiveSupport::NumberHelper.number_to_delimited(count)
      end

      def title
        return no_scanners_title if no_scanners_configured?
        return two_scanners_title if two_scanners_configured?
        return one_scanner_above_threshold_title if above_threshold?(configured_scanner_type)

        one_scanner_below_threshold_title
      end

      def no_scanners_title
        s_('ScanCoverageBanner|None of your active projects are scanned for security issues')
      end

      def two_scanners_title
        s_('ScanCoverageBanner|Security scanning runs on some projects, not most')
      end

      def one_scanner_above_threshold_title
        if configured_scanner_type == :sast
          s_('ScanCoverageBanner|Your projects check code, but not for leaked secrets')
        else
          s_('ScanCoverageBanner|Your projects check for leaked secrets, but not the code itself')
        end
      end

      def one_scanner_below_threshold_title
        format(
          s_('ScanCoverageBanner|%{scanner} runs on %{count} of your %{total} projects'),
          scanner: scanner_label_capitalized(configured_scanner_type),
          count: delimited(count_for(configured_scanner_type)),
          total: delimited(total_projects_count)
        )
      end

      def message
        return no_scanners_message if no_scanners_configured?
        return two_scanners_message if two_scanners_configured?
        return one_scanner_above_threshold_message if above_threshold?(configured_scanner_type)

        one_scanner_below_threshold_message
      end

      def no_scanners_message
        format(
          s_('ScanCoverageBanner|None of your %{active} projects are covered by application security testing. ' \
            'Set up scanning once to cover them all.'),
          active: delimited(total_projects_count)
        )
      end

      def one_scanner_above_threshold_message
        return sast_above_threshold_message if configured_scanner_type == :sast

        secret_detection_above_threshold_message
      end

      def sast_above_threshold_message
        format(
          s_('ScanCoverageBanner|%{count} of %{total} projects run application security testing. Add secret ' \
            "detection to the same projects to catch passwords and keys before they're merged."),
          count: delimited(count_for(:sast)),
          total: delimited(total_projects_count)
        )
      end

      def secret_detection_above_threshold_message
        format(
          s_('ScanCoverageBanner|%{count} of %{total} projects scan for secrets. Add application security ' \
            "testing to the same projects to catch vulnerabilities before they're merged."),
          count: delimited(count_for(:secret_detection)),
          total: delimited(total_projects_count)
        )
      end

      def one_scanner_below_threshold_message
        format(
          s_("ScanCoverageBanner|You've already set it up. Add it to the other %{remaining} projects to cover " \
            'the whole group.'),
          remaining: delimited(total_projects_count - count_for(configured_scanner_type))
        )
      end

      def two_scanners_message
        format(
          s_('ScanCoverageBanner|%{scanner_a} covers %{count_a} of %{total} projects and %{scanner_b} covers ' \
            '%{count_b}. Bring every project in the group up to the same coverage.'),
          scanner_a: scanner_label_capitalized(:sast),
          count_a: delimited(count_for(:sast)),
          scanner_b: scanner_label(:secret_detection),
          count_b: delimited(count_for(:secret_detection)),
          total: delimited(total_projects_count)
        )
      end

      def cta_text
        return s_('ScanCoverageBanner|Apply recommended profile') if no_scanners_configured?
        return s_('ScanCoverageBanner|Apply recommended profile') if two_scanners_configured?
        return one_scanner_above_threshold_cta_text if above_threshold?(configured_scanner_type)

        format(
          s_('ScanCoverageBanner|Add %{scanner} to more projects'),
          scanner: scanner_label(configured_scanner_type)
        )
      end

      def one_scanner_above_threshold_cta_text
        if configured_scanner_type == :sast
          s_('ScanCoverageBanner|Add secret detection')
        else
          s_('ScanCoverageBanner|Add application security testing')
        end
      end

      def cta_url
        ::Gitlab::Routing.url_helpers.group_security_configuration_path(group, anchor: '/enable_scanners/approach')
      end

      def banner_type
        return 'no_scanners' if no_scanners_configured?
        return 'two_scanners' if two_scanners_configured?

        above_threshold?(configured_scanner_type) ? 'single_scanner_high' : 'single_scanner_low'
      end
    end
  end
end
