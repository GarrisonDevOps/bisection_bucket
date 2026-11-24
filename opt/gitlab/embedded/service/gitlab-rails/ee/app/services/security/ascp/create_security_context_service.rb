# frozen_string_literal: true

module Security
  module Ascp
    class CreateSecurityContextService
      MAX_GUIDELINES = 100

      def initialize(current_user:, project:, params:)
        @current_user = current_user
        @project = project
        @params = params
      end

      def execute
        validation_error = validate
        return validation_error if validation_error

        create_security_context
      rescue ActiveRecord::RecordInvalid => e
        ServiceResponse.error(message: e.record.errors.full_messages.to_sentence)
      end

      private

      attr_reader :current_user, :project, :params

      def validate
        validate_permission ||
          validate_component ||
          validate_scan ||
          validate_guidelines_presence ||
          validate_guidelines
      end

      def validate_permission
        return if Ability.allowed?(current_user, :create_ascp_security_context, project)

        ServiceResponse.error(message: 'Insufficient permissions')
      end

      def validate_component
        return if component

        ServiceResponse.error(message: 'Component not found in this project')
      end

      def validate_scan
        return if scan

        ServiceResponse.error(message: 'Scan not found in this project')
      end

      def validate_guidelines_presence
        return ServiceResponse.error(message: 'Guidelines must not be empty') if params[:guidelines].blank?

        return unless params[:guidelines].size > MAX_GUIDELINES

        ServiceResponse.error(message: "Maximum #{MAX_GUIDELINES} guidelines allowed")
      end

      def validate_guidelines
        error = nil

        params[:guidelines].each_with_index do |guideline, i|
          error = guideline_error(guideline, i)
          break if error
        end

        error
      end

      def guideline_error(guideline, index)
        prefix = "Guideline #{index + 1}"

        return ServiceResponse.error(message: "#{prefix}: name can't be blank") if guideline[:name].blank?
        return ServiceResponse.error(message: "#{prefix}: operation can't be blank") if guideline[:operation].blank?

        if guideline[:name].to_s.length > 255
          return ServiceResponse.error(message: "#{prefix}: name is too long (maximum is 255 characters)")
        end

        return unless guideline[:operation].to_s.length > 1024

        ServiceResponse.error(message: "#{prefix}: operation is too long (maximum is 1024 characters)")
      end

      def create_security_context
        SecApplicationRecord.transaction do
          security_context = SecurityContext.create!(
            project: project,
            component: component,
            scan: scan,
            summary: params[:summary],
            authentication_model: params[:authentication_model],
            authorization_model: params[:authorization_model],
            data_sensitivity: params[:data_sensitivity],
            security_boundary: params[:security_boundary] || []
          )

          bulk_insert_guidelines(security_context)

          ServiceResponse.success(payload: { security_context: security_context })
        end
      end

      def component
        @component ||= Component.find_for_project(params[:component_id], project.id)
      end

      def scan
        @scan ||= Scan.find_for_project(params[:scan_id], project.id)
      end

      def bulk_insert_guidelines(security_context)
        now = Time.current
        records = params[:guidelines].map do |guideline|
          {
            project_id: project.id,
            scan_id: scan.id,
            security_context_id: security_context.id,
            name: guideline[:name],
            operation: guideline[:operation],
            legitimate_use: guideline[:legitimate_use],
            security_boundary: guideline[:security_boundary],
            business_context: guideline[:business_context],
            severity_if_violated: SecurityGuideline.severity_if_violateds[
              guideline[:severity_if_violated]&.to_s || 'medium'
            ],
            created_at: now,
            updated_at: now
          }
        end

        SecurityGuideline.insert_all!(records)
      end
    end
  end
end
