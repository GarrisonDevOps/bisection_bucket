# frozen_string_literal: true

module API
  # This API endpoint handles interaction payloads sent from Slack.
  # See https://api.slack.com/interactivity/handling.
  class Integrations
    module Slack
      class Interactions < ::API::Base
        include Slack::Concerns::VerifiesRequest
        include Slack::Concerns::LimitsWorkspaceRequests

        feature_category :integrations

        namespace 'integrations/slack' do
          desc 'Process Slack interaction events' do
            detail 'Processes interaction events from Slack'
            tags %w[integrations internal_operations]
          end
          route_setting :authorization, skip_granular_token_authorization: :slack_signature_auth
          post :interactions, urgency: :low do
            service_params = Gitlab::Json.safe_parse(params[:payload]).deep_symbolize_keys!

            status :ok

            next {} if slack_workspace_throttled?(:slack_app_interactions, service_params.dig(:team, :id))

            response = ::Integrations::SlackInteractionService.new(service_params).execute

            response.payload
          rescue StandardError => e
            Gitlab::ErrorTracking.track_exception(e)

            no_content!
          end
        end
      end
    end
  end
end
