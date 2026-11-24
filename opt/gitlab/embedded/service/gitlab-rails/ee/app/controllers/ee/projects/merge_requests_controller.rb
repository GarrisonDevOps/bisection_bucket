# frozen_string_literal: true

module EE
  module Projects
    module MergeRequestsController
      extend ActiveSupport::Concern

      prepended do
        include DescriptionDiffActions
        include GeoInstrumentation

        before_action only: [:show] do
          push_frontend_feature_flag(:merge_trains_skip_train, @project)
          push_frontend_ability(ability: :resolve_vulnerability_with_ai, resource: @project, user: current_user)
          # Whether this project offers Standard reviews, not just the flag; the depth pickers read it.
          push_force_frontend_feature_flag(:duo_code_review_standard_flow,
            ::Gitlab::Duo::CodeReview.standard_available?(project: @project))
        end

        before_action only: [:show, :diffs] do
          push_frontend_feature_flag(:agent_presence_consolidation, project.root_ancestor)
        end

        before_action :authorize_read_pipeline!, only: [:metrics_reports]
        before_action :authorize_read_licenses!, only: [:license_scanning_reports, :license_scanning_reports_collapsed]
        before_action :set_application_context!, only: [:show, :diffs, :commits, :pipelines]

        after_action :display_duo_seat_warning, only: [:update]

        feature_category :code_testing, [:metrics_reports]
        feature_category :software_composition_analysis,
          [:license_scanning_reports, :license_scanning_reports_collapsed]
        feature_category :code_review_workflow, [:delete_description_version, :description_diff]

        urgency :high, [:delete_description_version]
        urgency :low, %i[
          metrics_reports
          description_diff
          license_scanning_reports
          license_scanning_reports_collapsed
        ]
      end

      def license_scanning_reports
        reports_response(merge_request.compare_license_scanning_reports(current_user))
      end

      def license_scanning_reports_collapsed
        reports_response(merge_request.compare_license_scanning_reports_collapsed(current_user))
      end

      def metrics_reports
        reports_response(merge_request.compare_metrics_reports(current_user))
      end
    end
  end
end
