# frozen_string_literal: true

module API
  class DependencyListExports < ::API::Base
    feature_category :dependency_management
    urgency :low

    before do
      authenticate!
    end

    helpers do
      def find_export
        ::Dependencies::DependencyListExport.find_by_id(params[:export_id].to_i) || not_found!
      end

      def present_created_export(result)
        if result.success?
          present result.payload[:dependency_list_export], with: ::API::Entities::DependencyListExport
        else
          render_api_error!(result.message, :unprocessable_entity)
        end
      end
    end

    resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      params do
        requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the project.'

        optional :send_email, type: Boolean, default: false, desc: 'If `true`, sends an email notification to the ' \
                                                               'requesting user when the export completes.'
        optional :export_type, type: Symbol,
          values: %i[dependency_list csv cyclonedx_1_6_json],
          default: :dependency_list,
          desc: 'Format of the export.'
      end
      desc 'Create a dependency list export' do
        detail 'Creates a CycloneDX JSON export for all the project dependencies detected in a pipeline. If an ' \
          'authenticated user does not have the read_dependency permission, this request returns a `403 Forbidden` ' \
          'status code.'
        tags ['dependency_management']
      end
      route_setting :tier, :ultimate
      route_setting :authorization, permissions: :create_dependency_list_export, boundary_type: :project
      post ':id/dependency_list_exports' do
        authorize! :read_dependency, user_project

        result = ::Dependencies::CreateExportService.new(user_project, current_user, params).execute

        present_created_export(result)
      end
    end

    resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      params do
        requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the group.'

        optional :send_email, type: Boolean, default: false, desc: 'If `true`, sends an email notification to the ' \
                                                               'requesting user when the export completes.'
        optional :export_type, type: Symbol, values: %i[json_array csv], default: :json_array,
          desc: 'Format of the export.'
      end
      desc 'Create a dependency list export' do
        detail 'Creates a CycloneDX JSON export for all the project dependencies detected in a pipeline. If an ' \
          'authenticated user does not have the read_dependency permission, this request returns a `403 Forbidden` ' \
          'status code.'
        tags ['dependency_management']
      end
      route_setting :tier, :ultimate
      route_setting :authorization, permissions: :create_dependency_list_export, boundary_type: :group
      post ':id/dependency_list_exports' do
        authorize! :read_dependency, user_group

        result = ::Dependencies::CreateExportService.new(user_group, current_user, params).execute

        present_created_export(result)
      end
    end

    resource :pipelines do
      params do
        requires :id, types: [String, Integer], desc: 'ID of the pipeline.'

        optional :send_email, type: Boolean, default: false, desc: 'If `true`, sends an email notification to the ' \
                                                               'requesting user when the export completes.'
        optional :export_type, type: String, values: %w[sbom], default: 'sbom', desc: 'Format of the export.'
      end
      desc 'Create a dependency list export' do
        detail 'Creates a CycloneDX JSON export for all the project dependencies detected in a pipeline. If an ' \
          'authenticated user does not have the read_dependency permission, this request returns a `403 Forbidden` ' \
          'status code.'
        tags ['dependency_management']
      end
      route_setting :tier, :ultimate
      route_setting :authorization, permissions: :create_dependency_list_export,
        boundary: -> { user_pipeline.project }, boundary_type: :project
      post ':id/dependency_list_exports' do
        authorize! :read_dependency, user_pipeline

        result = ::Dependencies::CreateExportService.new(
          user_pipeline, current_user, params).execute

        present_created_export(result)
      end
    end

    params do
      requires :export_id, types: [Integer, String], desc: 'ID of the dependency list export.'
    end
    desc 'Retrieve a single dependency list export' do
      detail 'Retrieves a dependency list export.'
      tags ['dependency_management']
    end
    route_setting :tier, :ultimate
    route_setting :authorization, permissions: :read_dependency_list_export,
      boundary: -> { find_export.then { |e| e.project || e.group || e.pipeline&.project } },
      boundaries: [{ boundary_type: :project }, { boundary_type: :group }]
    get 'dependency_list_exports/:export_id' do
      dependency_list_export = find_export

      authorize! :read_dependency_list_export, dependency_list_export

      unless dependency_list_export.completed?
        ::Gitlab::PollingInterval.set_api_header(self, interval: 5_000)
        status :accepted
      end

      present dependency_list_export, with: ::API::Entities::DependencyListExport
    end

    desc 'Download dependency list export' do
      detail 'Downloads a dependency list export.'
      produces %w[application/octet-stream]
      success code: 200
      tags ['dependency_management']
    end
    route_setting :tier, :ultimate
    route_setting :authorization, permissions: :read_dependency_list_export,
      boundary: -> { find_export.then { |e| e.project || e.group || e.pipeline&.project } },
      boundaries: [{ boundary_type: :project }, { boundary_type: :group }]
    get 'dependency_list_exports/:export_id/download' do
      dependency_list_export = find_export

      authorize! :read_dependency_list_export, dependency_list_export

      if dependency_list_export.finished?
        present_carrierwave_file!(dependency_list_export.file, content_disposition: :attachment)
      else
        not_found!('DependencyListExport')
      end
    end
  end
end
