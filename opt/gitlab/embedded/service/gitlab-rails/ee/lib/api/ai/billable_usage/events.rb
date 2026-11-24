# frozen_string_literal: true

module API
  module Ai
    module BillableUsage
      class Events < ::API::Base
        include APIGuard

        feature_category :"self-hosted_models"
        urgency :low

        allow_access_with_scope :ai_features

        before do
          not_found! unless ::Ai::BillableUsage::IngestService.enabled?

          authenticate!

          forbidden!('Token must belong to a service account') unless current_user.service_account?
        end

        namespace :ai do
          namespace :billable_usage do
            namespace :events do
              desc 'Create Duo billing events from a Snowplow tracker payload' do
                detail 'Snowplow-compatible collector endpoint that receives Duo billing events from a ' \
                  'self-hosted AI gateway on an air-gapped instance. Requires a personal access token of a ' \
                  'service account with the ai_features scope. Available only when the ' \
                  'local_billing_persistence feature flag is enabled.'
                success code: 200
                failure [
                  { code: 400, message: 'Bad request' },
                  { code: 401, message: 'Unauthorized' },
                  { code: 403, message: 'Forbidden' },
                  { code: 404, message: 'Not found' }
                ]
                tags %w[gitlab_duo_workflows internal_operations]
                hidden true
              end
              route_setting :lifecycle, :experiment
              route_setting :authorization, todo: 'https://gitlab.com/gitlab-org/gitlab/-/work_items/631688'
              post 'com.snowplowanalytics.snowplow/tp2' do
                result = ::Ai::BillableUsage::IngestService.new(params[:data]).execute

                bad_request!(result.message) if result.error?

                status :ok
                present({ status: 'ok' }, with: Grape::Presenters::Presenter)
              end
            end
          end
        end
      end
    end
  end
end
