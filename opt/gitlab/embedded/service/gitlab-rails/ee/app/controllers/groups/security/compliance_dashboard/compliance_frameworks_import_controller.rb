# frozen_string_literal: true

module Groups
  module Security
    module ComplianceDashboard
      class ComplianceFrameworksImportController < Groups::ApplicationController
        before_action :authorize_admin_compliance_framework!
        feature_category :compliance_management

        def create
          if missing_params?
            return render json: { status: :error, message: 'No template file provided' },
              status: :unprocessable_entity
          end

          unless parse_json
            return render json: { status: :error, message: 'Invalid file format' },
              status: :unprocessable_entity
          end

          result = ComplianceManagement::Frameworks::JsonImportService.new(
            user: current_user,
            group: @group,
            json_payload: @json_payload
          ).execute

          respond_to do |format|
            format.json do
              if result.success?
                json_response = {
                  status: :success,
                  framework_id: result.payload[:framework].id
                }

                message = result.message.strip
                json_response[:message] = message unless message.empty?

                render json: json_response, status: :ok
              else
                render json: {
                  status: :error,
                  message: "#{result.message}, #{result.payload}"
                }, status: :unprocessable_entity
              end
            end
          end
        end

        private

        def missing_params?
          strong_params[:framework_file].nil?
        end

        def parse_json
          @json_payload = ::Gitlab::Json.safe_parse(json_content)
        rescue JSON::ParserError
          false
        end

        def json_content
          strong_params[:framework_file].read
        end

        def authorize_admin_compliance_framework!
          render_404 unless can?(current_user, :admin_compliance_framework, @group)
        end

        def strong_params
          params.permit(:framework_file)
        end
      end
    end
  end
end
