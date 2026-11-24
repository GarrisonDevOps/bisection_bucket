# frozen_string_literal: true

module API
  class License < ::API::Base
    before { authenticated_as_admin! }

    LICENSES_TAGS = %w[licenses].freeze
    feature_category :plan_provisioning
    urgency :low

    resource :license do
      desc 'Retrieve license information' do
        detail 'Retrieves information about the current license.'
        success ::API::Entities::GitlabLicenseWithActiveUsers
        failure [
          { code: 401, message: 'Unauthorized' },
          { code: 403, message: 'Forbidden' }
        ]
        tags LICENSES_TAGS
      end
      route_setting :authorization, permissions: :read_license, boundary_type: :instance, assignable_when: [:admin]
      get do
        license = ::License.current

        present license, with: ::API::Entities::GitlabLicenseWithActiveUsers
      end

      resource :usage_export do
        after do
          Gitlab::CurrentSettings.update(license_usage_data_exported: true) if ::License.current.offline_cloud_license?
        end

        desc 'Download license usage data' do
          detail 'Downloads usage data for the currently active license.'
          failure [
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' }
          ]
          tags LICENSES_TAGS
        end
        route_setting :authorization, permissions: :read_license, boundary_type: :instance, assignable_when: [:admin]
        get do
          license = ::License.current
          content_type MIME::Types.type_for('csv').first.content_type
          env['api.format'] = :txt
          body HistoricalUserData::CsvService.new(license.historical_data).generate
        end
      end

      desc 'Create a license' do
        detail 'Creates a license.'
        success ::API::Entities::GitlabLicenseWithActiveUsers
        failure [
          { code: 400, message: 'Bad request' }
        ]
        tags LICENSES_TAGS
      end
      params do
        requires :license, type: String, desc: 'License string.'
      end
      route_setting :authorization, permissions: :create_license, boundary_type: :instance, assignable_when: [:admin]
      post do
        license = ::License.new(data: params[:license])
        if license.save
          license.schedule_add_on_purchases_provisioning

          present license, with: ::API::Entities::GitlabLicenseWithActiveUsers
        else
          render_api_error!(license.errors.full_messages.first, 400)
        end
      end

      desc 'Retrieve a license' do
        detail 'Retrieves information about a specified license.'
        success ::API::Entities::GitlabLicenseWithActiveUsers
        failure [
          { code: 404, message: 'Not Found' },
          { code: 403, message: 'Forbidden' },
          { code: 401, message: 'Unauthorized' }
        ]
        tags LICENSES_TAGS
      end
      params do
        requires :id, type: Integer, desc: 'ID of the GitLab license.'
      end
      route_setting :authorization, permissions: :read_license, boundary_type: :instance, assignable_when: [:admin]
      get ':id' do
        license = LicensesFinder.new(current_user, id: params[:id]).execute.first

        not_found! unless license

        present license, with: ::API::Entities::GitlabLicenseWithActiveUsers
      end

      desc 'Delete a license' do
        detail 'Deletes a specified license.'
        success code: 204, message: 'Resource deleted'
        failure [
          { code: 404, message: 'Not found' }
        ]
        tags LICENSES_TAGS
      end
      params do
        requires :id, type: Integer, desc: 'ID of the GitLab license.'
      end
      route_setting :authorization, permissions: :delete_license, boundary_type: :instance, assignable_when: [:admin]
      delete ':id' do
        license = LicensesFinder.new(current_user, id: params[:id]).execute.first

        Licenses::DestroyService.new(license, current_user).execute

        no_content!
      end

      desc 'Trigger recalculation of billable users' do
        detail 'Triggers recalculation of billable users for a specified license.'
        success ::API::Entities::BasicSuccess
        failure [
          { code: 404, message: 'Not found' },
          { code: 403, message: 'Forbidden' },
          { code: 401, message: 'Unauthorized' },
          { code: 429, message: 'Too many requests' }
        ]
        tags LICENSES_TAGS
      end
      params do
        requires :id, type: Integer, desc: 'ID of the GitLab license.'
      end
      route_setting :authorization, permissions: :refresh_license_billable_user, boundary_type: :instance,
        assignable_when: [:admin]
      put ':id/refresh_billable_users' do
        license = LicensesFinder.new(current_user, id: params[:id]).execute.first

        not_found! unless license

        if Feature.enabled?(:throttle_refresh_billable_users, current_user)
          check_rate_limit!(:refresh_billable_users, scope: { user: current_user })
        end

        license.update_billable_user_counts

        status :accepted
        { success: true }
      end
    end

    resource :licenses do
      desc 'List all licenses' do
        detail 'Lists all information about all licenses.'
        success ::API::Entities::GitlabLicense
        failure [
          { code: 403, message: 'Forbidden' }
        ]
        is_array true
        tags LICENSES_TAGS
      end
      route_setting :authorization, permissions: :read_license, boundary_type: :instance, assignable_when: [:admin]
      get do
        licenses = LicensesFinder.new(current_user).execute

        present licenses, with: ::API::Entities::GitlabLicense, current_active_users_count: ::License.current&.daily_billable_users_count
      end
    end
  end
end
