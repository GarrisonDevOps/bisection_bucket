# frozen_string_literal: true

module Security
  module DependencyFirewall
    module PreventedStats
      class GroupRefreshService
        PURL_FLAGS = %i[blocked_7 warned_only_7 blocked_30 warned_only_30].freeze

        def initialize(group, batch_size: 500)
          @group = group
          @batch_size = batch_size
        end

        def execute
          window_starts = DependencyFirewallNamespacePreventedStat::WINDOWS.index_with do |days|
            (utc_today - (days - 1)).in_time_zone('UTC')
          end

          purls = merged_purls(window_starts)

          rows = window_starts.map { |days, from| stat_row(days, from, purls) }
          DependencyFirewallNamespacePreventedStat.upsert_all(rows, unique_by: %i[namespace_id window_days])
        end

        private

        attr_reader :group, :batch_size

        def merged_purls(window_starts)
          merged = {}

          project_ids.each_slice(batch_size) do |batch|
            DependencyFirewallPreventedPackage.window_flags(
              project_ids: batch, from_7: window_starts[7], from_30: window_starts[30]
            ).each do |row|
              existing = merged[[row[:card], row[:identifier]]]
              merged[[row[:card], row[:identifier]]] = existing ? merge(existing, row) : row
            end
          end

          merged.values
        end

        def utc_today
          Time.current.utc.to_date
        end

        def project_ids
          Gitlab::Database::NamespaceProjectIdsEachBatch.new(group_id: group.id).execute
        end

        def merge(left, right)
          merged = left.merge(right.slice(*PURL_FLAGS)) { |_, a, b| a || b }
          merged[:max_severity_7] = [left[:max_severity_7], right[:max_severity_7]].compact.max
          merged[:max_severity_30] = [left[:max_severity_30], right[:max_severity_30]].compact.max
          merged
        end

        def stat_row(days, from, purls)
          by_card = purls.group_by { |purl| purl[:card] }
          vulnerabilities = by_card.fetch('vulnerabilities', []).select { |purl| purl[:"blocked_#{days}"] }

          {
            namespace_id: group.id,
            window_days: days,
            window_start: from.to_date,
            vulnerabilities_prevented: vulnerabilities.size,
            malicious_packages_prevented: count_flag(by_card, 'malicious', :"blocked_#{days}"),
            malicious_packages_warned_only: count_flag(by_card, 'malicious', :"warned_only_#{days}"),
            license_risks_prevented: count_flag(by_card, 'license', :"blocked_#{days}"),
            license_risks_warned_only: count_flag(by_card, 'license', :"warned_only_#{days}")
          }.merge(severity_counts(vulnerabilities, days))
        end

        def count_flag(by_card, card, flag)
          by_card.fetch(card, []).count { |purl| purl[flag] }
        end

        def severity_counts(vulnerabilities, days)
          counts = vulnerabilities.map { |purl| purl.fetch(:"max_severity_#{days}") }.tally
          by_name = counts.each_with_object(Hash.new(0)) do |(severity_int, count), result|
            result[DependencyFirewallPreventedPackage.severities.key(severity_int) || 'unknown'] += count
          end

          DependencyFirewallNamespacePreventedStat::SEVERITIES.to_h { |name| [:"severity_#{name}", by_name[name]] }
        end
      end
    end
  end
end
