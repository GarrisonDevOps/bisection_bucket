# frozen_string_literal: true

module Vulnerabilities
  module Flags
    class UpdateAiDetectionService
      include Gitlab::Allowable
      include Gitlab::InternalEventsTracking
      include Gitlab::Utils::StrongMemoize

      AI_SAST_FP_DETECTION_ORIGIN = 'ai_sast_fp_detection'
      DESCRIPTION_MAX_LENGTH = 100_000

      REPORT_TYPE_EVENTS = {
        'sast' => 'reported_sast_vulnerability_false_positive_analysis',
        'secret_detection' => 'reported_secret_detection_vulnerability_false_positive_analysis'
      }.freeze

      def initialize(user, vulnerability, params)
        @user = user
        @vulnerability = vulnerability
        @params = params
        @project = vulnerability&.project
      end

      def execute
        return ServiceResponse.error(message: 'Vulnerability not found') unless vulnerability
        return ServiceResponse.error(message: 'Unauthorized') unless authorized?
        return ServiceResponse.error(message: 'No current finding available') unless current_finding

        update_flag
      end

      private

      attr_reader :user, :vulnerability, :params, :project

      def authorized?
        project && can?(user, :update_vulnerability_flag, project)
      end

      def current_finding
        # currently vulnerabilities only have a single finding but this is poised to change in the future
        @current_finding ||= vulnerability&.last_finding
      end

      def find_or_initialize_flag
        # rubocop:disable CodeReuse/ActiveRecord -- Need to instantiate a new record here if none exist yet
        current_finding.vulnerability_flags.find_or_initialize_by(
          flag_type: :false_positive,
          origin: params[:origin] || AI_SAST_FP_DETECTION_ORIGIN
        )
        # rubocop:enable CodeReuse/ActiveRecord
      end

      def flag
        @flag ||= find_or_initialize_flag
      end

      def update_flag
        confidence_score = normalize_confidence_score(params[:confidence_score])
        status = if confidence_score.nil?
                   Vulnerabilities::Flag::FALSE_POSITIVE_DETECTION_STATUSES[:failed]
                 else
                   detected_status_from_confidence(confidence_score)
                 end

        flag.assign_attributes(
          description: truncate_description(params[:description]) || flag.description,
          confidence_score: confidence_score || 0.0,
          project_id: project.id,
          status: status,
          workflow: parent_workflow
        )
        flag.parent_workflow_unresolved = flow_originated? && parent_workflow.nil?
        log_unresolved_parent_workflow if flag.parent_workflow_unresolved

        if flag.save
          ::Vulnerabilities::EsHelper.sync_elasticsearch([vulnerability.id])

          track_event if params[:confidence_score].present?

          ServiceResponse.success(payload: { flag: flag, is_new_flag: flag.saved_change_to_id? })
        else
          ServiceResponse.error(message: flag.errors.full_messages.join(', '))
        end
      end

      # With a composite identity token, `user` is the scoped human, so the flow is only
      # visible through the authentication link.
      def flow_originated?
        return false unless ::Feature.enabled?(:ai_flow_trigger_chaining, project.root_ancestor)

        ::Gitlab::Auth::Identity.resolve_composite_identity_actor(user) != user
      end
      strong_memoize_attr :flow_originated?

      # The resolution flow this flag can start joins the writing flow's chain, so it must not
      # act for anyone other than the human who started that chain.
      def parent_workflow
        return unless flow_originated?

        ::Ai::FlowTriggers::CallerContext.authorized_parent_workflow_for_request(user)
      end
      strong_memoize_attr :parent_workflow

      def log_unresolved_parent_workflow
        Gitlab::AppLogger.info(
          message: 'Flow-originated vulnerability flag without an authorized parent workflow, ' \
            'skipping the resolution workflow',
          vulnerability_id: vulnerability.id,
          Labkit::Fields::GL_PROJECT_ID => project.id
        )
      end

      def normalize_confidence_score(score)
        return if score.nil?

        # Convert 0-100 range to 0.0-1.0 range
        score.to_f / 100.0
      end

      def truncate_description(description)
        return description if description.blank?

        description.to_s.truncate(DESCRIPTION_MAX_LENGTH, omission: '')
      end

      def detected_status_from_confidence(score)
        statuses =
          Vulnerabilities::Flag::FALSE_POSITIVE_DETECTION_STATUSES

        threshold =
          ::Vulnerabilities::TriggerResolutionWorkflowWorker::CONFIDENCE_THRESHOLD

        if score < threshold
          statuses[:detected_as_not_fp]
        else
          statuses[:detected_as_fp]
        end
      end

      def track_event
        event_name = REPORT_TYPE_EVENTS[vulnerability.report_type.to_s]
        return unless event_name

        track_internal_event(
          event_name,
          user: user,
          project: project,
          additional_properties: {
            label: flag.origin,
            value: vulnerability.id,
            property: vulnerability.severity,
            confidence_score: params[:confidence_score].to_i
          }
        )
      end
    end
  end
end
