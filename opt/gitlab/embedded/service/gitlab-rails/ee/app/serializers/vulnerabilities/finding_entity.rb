# frozen_string_literal: true

class Vulnerabilities::FindingEntity < Grape::Entity
  include RequestAwareEntity
  include VulnerabilitiesHelper
  include MarkupHelper
  include Vulnerabilities::DetailSanitizer

  expose :id, :report_type, :name, :severity
  expose :scanner, using: Vulnerabilities::ScannerEntity
  expose :unverified, if: ->(finding, _) { finding.respond_to?(:unverified?) } do |finding, _|
    finding.unverified?
  end
  expose :identifiers, using: Vulnerabilities::IdentifierEntity, documentation: { is_array: true }
  expose :uuid
  expose :create_jira_issue_url do |occurrence|
    create_jira_issue_url_for(occurrence)
  end
  expose :false_positive?, as: :false_positive, if: ->(_, _) { expose_false_positive? }
  expose :create_vulnerability_feedback_issue_path do |occurrence|
    create_vulnerability_feedback_issue_path(occurrence.project)
  end
  expose :create_vulnerability_feedback_merge_request_path do |occurrence|
    create_vulnerability_feedback_merge_request_path(occurrence.project)
  end
  expose :create_vulnerability_feedback_dismissal_path do |occurrence|
    create_vulnerability_feedback_dismissal_path(occurrence.project)
  end

  expose :project, using: ::ProjectEntity

  # :deprecate_vulnerability_feedback
  # These fields should be considered deprecated and their use avoided. However they are provided
  # in case of rollback
  expose :dismissal_feedback, using: Vulnerabilities::FeedbackEntity
  expose :issue_feedback, using: Vulnerabilities::FeedbackEntity
  expose :merge_request_feedback, using: Vulnerabilities::FeedbackEntity
  # /:deprecate_vulnerability_feedback

  expose :state_transitions, using: Vulnerabilities::StateTransitionEntity, documentation: { is_array: true }
  expose :issue_links, using: Vulnerabilities::IssueLinkEntity, documentation: { is_array: true }
  expose :external_issue_links, using: Vulnerabilities::ExternalIssueLinkEntity, documentation: { is_array: true }
  expose :merge_request_links,
    using: Vulnerabilities::MergeRequestLinkEntity,
    documentation: { is_array: true } do |finding|
    finding.merge_request_links.select { |link| link.merge_request.present? }
  end

  expose :metadata, merge: true, if: ->(occurrence, _) { occurrence.raw_metadata } do
    expose :description do |model|
      model.respond_to?(:redacted_description) ? model.redacted_description : model.description
    end
    expose :description_html do |model|
      description = model.respond_to?(:redacted_description) ? model.redacted_description : model.description
      markdown(description)
    end
    expose :links
    expose :location do |model|
      if model.respond_to?(:secret_redacted?) && model.secret_redacted?
        model.location&.except('commit')
      else
        model.location
      end
    end
    expose :remediations
    expose :solution
    expose(:evidence) { |model, _| model.evidence&.dig(:summary) }
    expose(:request, using: Vulnerabilities::RequestEntity) { |model, _| model.evidence&.dig(:request) }
    expose(:response, using: Vulnerabilities::ResponseEntity) { |model, _| model.evidence&.dig(:response) }
    expose(:evidence_source) { |model, _| model.evidence&.dig(:source) }
    expose(:supporting_messages) { |model, _| model.evidence&.dig(:supporting_messages) }
    expose(:assets) { |model, _| model.assets }
  end

  expose :details do |finding|
    next {} if (finding.respond_to?(:secret_redacted?) && finding.secret_redacted?) || finding.details.blank?

    finding.details.transform_values do |detail|
      detail.is_a?(Hash) ? sanitize_detail(detail.with_indifferent_access) : detail
    end
  end
  expose :state
  expose :scan

  expose :blob_path do |occurrence|
    if occurrence.respond_to?(:secret_redacted?) && occurrence.secret_redacted?
      ''
    else
      occurrence.present(presenter_class: Vulnerabilities::FindingPresenter).blob_path
    end
  end

  expose :found_by_pipeline, if: ->(finding, _) { finding.respond_to?(:found_by_pipeline) || finding.pipeline&.iid } do
    expose(:iid) do |finding|
      finding.respond_to?(:found_by_pipeline) ? finding.found_by_pipeline&.iid : finding.pipeline&.iid
    end
  end

  expose :ai_resolution_enabled?, as: :ai_resolution_enabled, if: ->(finding, _) {
                                                                    finding.respond_to?(:ai_resolution_enabled?)
                                                                  }

  expose :matches_auto_dismiss_policy?, as: :matches_auto_dismiss_policy, if: ->(_, _) { expose_policy_fields? }

  expose :auto_severity_override, if: ->(finding, _) {
    finding.auto_severity_override.present? && expose_severity_override_fields?
  }

  alias_method :occurrence, :object

  def current_user
    request.current_user if request.respond_to?(:current_user)
  end

  private

  def expose_false_positive?
    project = occurrence.project
    project.licensed_feature_available?(:sast_fp_reduction)
  end

  def expose_policy_fields?
    project = occurrence.project
    ::Security::PolicyAvailability.any_available?(project)
  end

  def expose_severity_override_fields?
    project = occurrence.project
    ::Security::PolicyAvailability.any_available?(project)
  end
end

Vulnerabilities::FindingEntity.include_mod_with('ProjectsHelper')
