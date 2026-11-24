# frozen_string_literal: true

module API
  module Admin
    module Ai
      class Catalog < ::API::Base
        feature_category :ai_catalog_curation
        urgency :low

        before do
          authenticated_as_admin!
        end

        resources 'admin/ai_catalog' do
          desc 'Hydrate database with GitLab-managed external agents' do
            hidden true # Experimental
            detail 'Seeds the database with external agent definitions from the GitLab AI catalog.'
            success code: 201, message: '201 Created'
            failure [
              { code: 401, message: '401 Unauthorized' },
              { code: 403, message: '403 Forbidden' },
              { code: 422, message: '422 Unprocessable Entity' }
            ]
            tags %w[ai_catalog]
          end
          route_setting :lifecycle, :experiment
          route_setting :authorization, permissions: :create_ai_catalog_third_party_flow, boundary_type: :instance,
            assignable_when: [:admin]
          post 'seed_external_agents' do
            Gitlab::Ai::Catalog::ThirdPartyFlows::Seeder.run!

            output = { message: 'External agents seeded successfully' }
            present output, with: Grape::Presenters::Presenter
          rescue StandardError => error
            unprocessable_entity!(error.message)
          end
        end
      end
    end
  end
end
