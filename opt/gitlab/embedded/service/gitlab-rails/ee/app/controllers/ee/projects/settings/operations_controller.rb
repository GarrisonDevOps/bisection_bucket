# frozen_string_literal: true

module EE
  module Projects
    module Settings
      module OperationsController
        extend ::Gitlab::Utils::Override
        extend ActiveSupport::Concern

        prepended do
          helper_method :status_page_setting

          private

          def status_page_setting
            @status_page_setting ||= project.status_page_setting || project.build_status_page_setting
          end

          def sla_feature_available?
            ::IncidentManagement::IncidentSla.available_for?(@project)
          end
        end

        override :permitted_project_params
        def permitted_project_params
          permitted_params = super

          if can?(current_user, :update_status_page_setting, project)
            permitted_params.push(status_page_setting_params)
          end

          if sla_feature_available?
            incident_params_hash = permitted_params.find { |item| item.is_a?(Hash) && item.key?(:incident_management_setting_attributes) }
            if incident_params_hash
              incident_params = incident_params_hash[:incident_management_setting_attributes]
              incident_params.push(*sla_timer_params)
            end
          end

          if can?(current_user, :update_observability_alert_setting, project)
            permitted_params.push(:observability_alerts_enabled)
          end

          permitted_params
        end

        def status_page_setting_params
          { status_page_setting_attributes: [:status_page_url, :aws_s3_bucket_name, :aws_region, :aws_access_key, :aws_secret_key, :enabled] }
        end

        def sla_timer_params
          [:sla_timer, :sla_timer_minutes]
        end
      end
    end
  end
end
