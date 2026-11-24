# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    module ComplianceRequirements
      class TriggerExternalControlService < BaseProjectService
        attr_accessor :control

        def initialize(project, control)
          @control = control

          super(project: project)
        end

        def execute
          return unless control.external?

          mark_compliance_status_pending!
          response = send_external_request
          handle_response(response)
        rescue ActiveRecord::RecordInvalid => invalid
          retry if should_retry?(invalid)

          ServiceResponse.error(message: invalid.record&.errors&.full_messages&.join(', '))
        rescue *::Gitlab::HTTP_V2::HTTP_ERRORS => e
          handle_http_error(e)
        end

        private

        def mark_compliance_status_pending!
          @project_control_compliance_status = ComplianceManagement::ComplianceFramework::ProjectControlComplianceStatus
                                                 .create_or_find_for_project_and_control(project, control)

          @project_control_compliance_status.pending!
        end

        def send_external_request
          # rubocop: disable CodeReuse/Serializer -- We serialize project and send the payload to the user's external service.
          # This is performed through a background job and therefore we cannot use controllers.
          project_data = ::ProjectSerializer.new.represent(project, serializer: :project_details)
          # rubocop: enable CodeReuse/Serializer

          project_data[:project_control_compliance_status] = @project_control_compliance_status.as_json

          body = Gitlab::Json::LimitedEncoder.encode(project_data)
          headers = { 'Content-Type' => 'application/json' }
          headers['X-GitLab-Signature'] = OpenSSL::HMAC.hexdigest('sha256', control.secret_token, body)

          Gitlab::HTTP.post(control.external_url, headers: headers, body: body)
        end

        def handle_response(response)
          if response.success?
            audit_success(response.code)

            ComplianceManagement::TimeoutPendingExternalControlsWorker.perform_in(31.minutes,
              { 'control_id' => control.id, 'project_id' => project.id })

            ServiceResponse.success(payload: { control: control })
          else
            audit_error(Rack::Utils::HTTP_STATUS_CODES[response.code], response.code)

            ServiceResponse.error(message: "External control service responded with an error. HTTP #{response.code}",
              reason: Rack::Utils::HTTP_STATUS_CODES[response.code])
          end
        end

        def handle_http_error(err)
          audit_error(err.message)
          ServiceResponse.error(message: err.message, reason: :network_error)
        end

        def should_retry?(invalid)
          # Handle race condition if two instances of this service were executed at the same time.
          # In such cases both of them might not find records, however, one of them will error out while creating.
          invalid.record&.errors&.of_kind?(:project, :taken)
        end

        def audit_success(http_code)
          message = "Request to compliance requirement external control with URL #{control.external_url} successful."
          message += " HTTP #{http_code}"

          audit_context = {
            name: 'request_to_compliance_external_control_successful',
            author: ::Gitlab::Audit::UnauthenticatedAuthor.new(name: '(System)'),
            scope: project,
            target: control,
            target_details: "External control",
            message: message
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end

        def audit_error(error_message, http_code = nil)
          message = "Request to compliance requirement external control with URL #{control.external_url} failed."
          message += " HTTP #{http_code}" if http_code
          message += " #{error_message}"

          audit_context = {
            name: 'request_to_compliance_external_control_failed',
            author: ::Gitlab::Audit::UnauthenticatedAuthor.new(name: '(System)'),
            scope: project,
            target: control,
            target_details: "External control",
            message: message.strip.truncate(1000)
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end
      end
    end
  end
end
