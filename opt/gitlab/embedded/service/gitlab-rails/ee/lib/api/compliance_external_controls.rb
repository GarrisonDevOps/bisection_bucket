# frozen_string_literal: true

module API
  class ComplianceExternalControls < ::API::Base
    VALID_STATUS_VALUES = %w[pass fail not_applicable].freeze
    VERIFICATION_TIMESTAMP_EXPIRY = 15.seconds
    HMAC_ALGORITHM = 'SHA256'
    SIGNATURE_HEADER = 'X-Gitlab-Hmac-Sha256'
    TIMESTAMP_HEADER = 'X-Gitlab-Timestamp'
    NONCE_HEADER = 'X-Gitlab-Nonce'
    NONCE_NAMESPACE = 'control_statuses:nonce'
    NONCE_LENGTH = 32
    feature_category :compliance_management

    params do
      requires :id, types: [String, Integer],
        desc: 'ID or URL-encoded path of the project.',
        documentation: { example: 1 }
    end
    resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      helpers do
        def verify_hmac_signature!(control)
          return error!('Control is not external', :forbidden) unless control.external?
          return error!('Missing required headers', :unauthorized) unless valid_hmac_headers?

          timestamp = headers[TIMESTAMP_HEADER]
          nonce = headers[NONCE_HEADER]

          return error!('Invalid nonce', :unauthorized) if malformed_nonce?(nonce)

          error!('Invalid signature', :unauthorized) unless valid_signature?(control, params, timestamp, nonce)
          error!('Invalid timestamp', :unauthorized) if invalid_timestamp?(timestamp)
          error!('Request has expired', :unauthorized) if expired_request?(timestamp)
          error!('Invalid nonce', :unauthorized) unless claim_nonce(nonce)
        end

        def expired_request?(timestamp)
          Time.current.to_i - timestamp.to_i >= VERIFICATION_TIMESTAMP_EXPIRY
        end

        def invalid_timestamp?(timestamp)
          timestamp.to_i == 0 || timestamp.to_i > Time.current.to_i
        end

        def valid_hmac_headers?
          [TIMESTAMP_HEADER, NONCE_HEADER, SIGNATURE_HEADER].all? { |header| headers[header].present? }
        end

        def valid_signature?(control, params, timestamp, nonce)
          path = "/api/v4/projects/#{params[:id]}/compliance_external_controls/#{params[:control_id]}/status"
          data = "status=#{params[:status]}"
          sign_payload = "#{timestamp}#{nonce}#{path}#{data}"

          expected_signature = OpenSSL::HMAC.hexdigest(
            HMAC_ALGORITHM,
            control.secret_token,
            sign_payload
          )

          ActiveSupport::SecurityUtils.secure_compare(headers[SIGNATURE_HEADER], expected_signature)
        end

        def valid_project(control)
          project = find_project(params[:id])
          error!('Project not found', :not_found) if project.nil?

          unless project.licensed_feature_available?(:custom_compliance_frameworks)
            return error!('Not permitted to update compliance control status',
              :unauthorized)
          end

          return project if control.compliance_requirement.framework.project_settings.by_project_id(project.id).any?

          error!('Project not found', :not_found)
        end

        def valid_control(control_id)
          control = ComplianceManagement::ComplianceFramework::ComplianceRequirementsControl.find_by_id(control_id)
          error!('Control not found', :not_found) if control.nil?

          control
        end

        def malformed_nonce?(nonce)
          nonce.blank? || nonce.length != NONCE_LENGTH
        end

        # SET NX checks and stores in one step, so two concurrent replays cannot both succeed.
        def claim_nonce(nonce)
          Gitlab::Redis::SharedState.with do |redis|
            redis.set(nonce_key(nonce), '1', ex: VERIFICATION_TIMESTAMP_EXPIRY.to_i + 1, nx: true)
          end
        end

        def nonce_key(nonce)
          "#{NONCE_NAMESPACE}:#{nonce}"
        end
      end

      desc 'Set status of an external control' do
        detail 'Sets the status of a specified external control. Use this operation to inform GitLab that a ' \
          'control has passed or failed a check by an external service.'
        tags ['compliance_policy_settings']
      end
      params do
        requires :control_id, type: Integer, desc: 'ID of the control.'
        requires :status, type: String, values: VALID_STATUS_VALUES, desc: 'Status of the control.'
      end
      route_setting :authorization, skip_granular_token_authorization: :compliance_external_auth
      patch ':id/compliance_external_controls/:control_id/status' do
        control = valid_control(params[:control_id])
        verify_hmac_signature!(control)
        project = valid_project(control)
        user = ::Gitlab::Audit::UnauthenticatedAuthor.new
        status = ComplianceManagement::ComplianceFramework::ComplianceRequirementsControls::UpdateStatusService.new(
          current_user: user,
          control: control,
          project: project,
          status_value: params[:status],
          params: { refresh_requirement_status: true }
        ).execute

        if status.success?
          status.payload
        else
          error!(status.message, :bad_request)
        end
      end
    end
  end
end
