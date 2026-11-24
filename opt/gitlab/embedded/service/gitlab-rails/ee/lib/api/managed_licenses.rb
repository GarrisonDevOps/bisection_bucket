# frozen_string_literal: true

module API
  class ManagedLicenses < ::API::Base
    include PaginationParams

    feature_category :security_policy_management
    urgency :low

    before { authenticate! unless route.settings[:skip_authentication] }

    helpers do
      def authorize_can_read!
        authorize!(:read_software_license_policy, user_project)
      end

      def authorize_can_admin!
        authorize!(:admin_software_license_policy, user_project)
      end

      def deprecation_message
        docs_page = Rails.application.routes.url_helpers.help_page_url(
          'user/compliance/license_approval_policies.md')

        'License-Check feature and Managed License API endpoint were removed. ' \
          'Users who wish to continue to enforce approvals based on detected licenses are encouraged ' \
          'to use the Scan Result Policies feature instead. ' \
          "See #{docs_page}"
      end
    end

    params do
      requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the project.'
    end

    resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      desc 'List all software license policies' do
        detail 'Lists all software license policies for a specified project.'
        success code: 200, model: ::API::Entities::ManagedLicense
        tags ['licenses']
        failure [
          { code: 401, message: 'Unauthorized' },
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' }
        ]
        is_array true
      end
      route_setting :skip_authentication, true
      params do
        use :pagination
      end
      route_setting :authorization, skip_granular_token_authorization: :deprecated_endpoint
      get ':id/managed_licenses' do
        authorize_can_read!

        present []
      end

      desc 'Retrieve a software license policy' do
        detail 'Retrieves a specified software license policy from a project.'
        success code: 200, model: ::API::Entities::ManagedLicense
        tags ['licenses']
        failure [
          { code: 401, message: 'Unauthorized' },
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' }
        ]
      end
      params do
        requires :managed_license_id, type: String, desc: 'ID of the managed license.'
      end
      route_setting :authorization, skip_granular_token_authorization: :deprecated_endpoint
      get ':id/managed_licenses/:managed_license_id', requirements: { managed_license_id: /.*/ } do
        authorize_can_read!

        present []
      end

      desc 'Create a software license policy' do
        detail 'Creates a software license policy for a specified project.'
        success code: 201, model: ::API::Entities::ManagedLicense
        tags ['licenses']
        failure [
          { code: 400, message: 'Bad Request' },
          { code: 401, message: 'Unauthorized' },
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' }
        ]
      end
      params do
        requires :name, type: String, desc: 'Name of the license.', documentation: { example: 'MIT' }
        requires :approval_status,
          type: String,
          values: ::SoftwareLicensePolicy.approval_status_values,
          desc: 'Approval status of the license.',
          documentation: { example: 'allowed' }
      end
      route_setting :authorization, skip_granular_token_authorization: :deprecated_endpoint
      post ':id/managed_licenses' do
        authorize_can_admin!

        bad_request!(deprecation_message)
      end

      desc 'Update a software license policy' do
        detail 'Updates a specified software license policy for a project.'
        success code: 200, model: ::API::Entities::ManagedLicense
        tags ['licenses']
        failure [
          { code: 400, message: 'Bad Request' },
          { code: 401, message: 'Unauthorized' },
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' }
        ]
      end
      params do
        requires :managed_license_id, type: String, desc: 'ID of the managed license.'
        optional :name, type: String, desc: 'Name of the license.', documentation: { example: 'MIT' }
        optional :approval_status,
          type: String,
          values: ::SoftwareLicensePolicy.approval_status_values,
          desc: 'Approval status of the license.',
          documentation: { example: 'allowed' }
      end
      route_setting :authorization, skip_granular_token_authorization: :deprecated_endpoint
      patch ':id/managed_licenses/:managed_license_id', requirements: { managed_license_id: /.*/ } do
        authorize_can_admin!

        bad_request!(deprecation_message)
      end

      desc 'Delete a software license policy' do
        detail 'Deletes a specified software license policy from a project.'
        success code: 204
        tags ['licenses']
        failure [
          { code: 401, message: 'Unauthorized' },
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' }
        ]
      end
      params do
        requires :managed_license_id, type: String, desc: 'ID of the managed license.'
      end
      route_setting :authorization, skip_granular_token_authorization: :deprecated_endpoint
      delete ':id/managed_licenses/:managed_license_id', requirements: { managed_license_id: /.*/ } do
        authorize_can_admin!

        bad_request!(deprecation_message)
      end
    end
  end
end
