# frozen_string_literal: true

module Vulnerabilities
  class RiskScore
    attr_reader :severity, :epss_score, :is_known_exploit

    def self.from_finding(finding)
      new(
        severity: finding.severity,
        epss_score: finding.cve_enrichment&.epss_score,
        is_known_exploit: finding.cve_enrichment&.is_known_exploit
      )
    end

    def initialize(**variables)
      @severity = variables[:severity]
      @epss_score = variables[:epss_score] || 0
      @is_known_exploit = !!variables[:is_known_exploit]
    end

    def score
      # TODO: Add links to the risk score calculation docs.
      [1.0, total_score].min
    end

    private

    def total_score
      base_score + epss_modifier + kev_modifier
    end

    def base_score
      case severity
      when 'critical' then 0.6
      when 'high' then 0.4
      when 'medium', 'unknown' then 0.2
      when 'low' then 0.05
      else 0
      end
    end

    def epss_modifier
      epss_base_modifier + epss_bonus
    end

    def epss_base_modifier
      epss_score * 0.3
    end

    def epss_bonus
      if epss_score >= 0.5
        0.2
      elsif epss_score >= 0.1
        0.1
      else
        0
      end
    end

    def kev_modifier
      if is_known_exploit
        0.3
      else
        0
      end
    end
  end
end
