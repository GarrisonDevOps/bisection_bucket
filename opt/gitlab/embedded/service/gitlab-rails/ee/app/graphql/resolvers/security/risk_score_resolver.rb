# frozen_string_literal: true

module Resolvers
  module Security
    class RiskScoreResolver < VulnerabilitiesBaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      type Types::Security::RiskScoreType, null: true

      authorize :read_security_resource

      argument :has_resolution, GraphQL::Types::Boolean,
        required: false,
        default_value: false,
        replace_null_with_default: true,
        description: 'Filters vulnerabilities by whether they are no longer detected on the default branch. ' \
          'If true, includes only those vulnerabilities. If false (default), excludes them.'

      def resolve(has_resolution:)
        authorize!(object) unless resolve_vulnerabilities_for_instance_security_dashboard?
        validate_advanced_vuln_management!

        base_params = build_base_params(has_resolution)

        risk_score_data = fetch_risk_score_data(base_params)

        transform_risk_score_data(risk_score_data)
      end

      private

      def build_base_params(has_resolution)
        project_ids = context[:project_id]
        tracked_context_id = context[:tracked_ref_ids]

        {
          project_id: project_ids,
          group_by: multi_project_scope? ? :project : nil,
          security_project_tracked_context_id: tracked_context_id,
          has_resolution: has_resolution
        }.compact
      end

      def multi_project_scope?
        vulnerable.is_a?(Group) || vulnerable.is_a?(::Organizations::Organization)
      end

      # An organization's projects span multiple top-level groups, so it exposes them via
      # `#projects` rather than the group-only `#all_projects` traversal.
      def vulnerable_projects
        vulnerable.is_a?(::Organizations::Organization) ? vulnerable.projects : vulnerable.all_projects
      end

      def fetch_risk_score_data(params)
        finder = ::Search::AdvancedFinders::Security::Vulnerability::RiskScoresFinder.new(vulnerable, params)
        finder.execute
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e)
        nil
      end

      def transform_risk_score_data(risk_score_data)
        return if risk_score_data.nil? || risk_score_data.empty?

        normalized_score = normalize_score(risk_score_data[:total_risk_score])

        result = {
          score: normalized_score,
          rating: rating(normalized_score),
          project_count: risk_score_data[:total_project_count] || 0
        }

        by_project = projects_data(risk_score_data[:risk_score_by_project]) if multi_project_scope?
        result[:by_project] = by_project if by_project

        result
      end

      def projects_data(risk_score_by_project_data)
        return if risk_score_by_project_data.nil? || risk_score_by_project_data.empty?

        project_ids = risk_score_by_project_data.keys

        projects = vulnerable_projects.id_in(project_ids).public_or_visible_to_user(current_user)

        projects.map do |project|
          normalized_score = normalize_score(risk_score_by_project_data[project.id])

          {
            project: project,
            score: normalized_score,
            rating: rating(normalized_score)
          }
        end
      end

      def normalize_score(score)
        return if score.nil?

        (score * 100).round(1)
      end

      def rating(score)
        case score
        when 0..25.9 then 'low'
        when 26..50.9 then 'medium'
        when 51..75.9 then 'high'
        when 76..100 then 'critical'
        else 'unknown'
        end
      end
    end
  end
end
