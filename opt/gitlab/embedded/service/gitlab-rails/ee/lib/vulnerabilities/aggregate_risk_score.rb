# frozen_string_literal: true

module Vulnerabilities
  class AggregateRiskScore
    # Todo - The actual diversity factor calculation requires
    # the unique cwe count among all vulnerabilities which,
    # we don't have a way to find out right now. So keeping this a constant.
    # More info - https://gitlab.com/groups/gitlab-org/-/epics/17002#note_2442241535
    DIVERSITY_FACTOR = 0.4

    # Calculate aggregate risk score for scoped vulnerabilities
    # This can be for a group or a project or any set of vulnerabilities.
    # Risk Score = (Sum(Vulnerability Scores) + Sum(Vulnerability_age_in_month) x 0.005) / sqrt(num_vulnerabilities)
    #
    # Arguments -
    #
    #   risk_score_sum: sum of all vulnerability finding risk scores
    #   created_at_sum: sum of epoch values for created_at, in milliseconds
    #   active_vulnerabilities_count: number of active vulnerabilities
    def self.score(risk_scores_sum:, created_at_sum:, active_vulnerabilities_count:)
      return 0.0 if active_vulnerabilities_count == 0

      # division by 1000 because created_at_sum is in milli seconds where as Time.zone.now.to_f gives seconds
      date_diff = (active_vulnerabilities_count * Time.zone.now.to_f) - (created_at_sum / 1000)
      date_diff_in_months = date_diff / 86400 / 30
      age_modifier = 0.005 * date_diff_in_months

      [
        1.0,
        total_risk_score(risk_scores_sum, age_modifier, active_vulnerabilities_count)
      ].min
    end

    def self.total_risk_score(risk_scores_sum, age_modifier, active_vulnerabilities_count)
      (DIVERSITY_FACTOR * ((risk_scores_sum + age_modifier) / Math.sqrt(active_vulnerabilities_count))).round(4).to_f
    end
    private_class_method :total_risk_score
  end
end
