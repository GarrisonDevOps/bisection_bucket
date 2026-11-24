# frozen_string_literal: true

module API
  module Ci
    class RunnerControllers < ::API::Base
      include ::API::PaginationParams

      feature_category :continuous_integration
      before do
        authenticated_as_admin!

        not_found! unless ::License.feature_available?(:ci_runner_controllers)
      end

      resource :runner_controllers do
        route_setting :lifecycle, :experiment

        desc 'List all runner controllers' do
          detail 'Lists all runner controllers.'
          is_array true
          success Entities::Ci::RunnerController
          tags %w[runner_controllers]
          failure [
            { code: 403, message: 'Forbidden' }
          ]
        end
        params do
          use :pagination
        end
        route_setting :lifecycle, :experiment
        route_setting :tier, :ultimate
        route_setting :authorization, permissions: :read_runner_controller, boundary_type: :instance,
          assignable_when: [:admin]
        get do
          controllers = ::Ci::RunnerController.all

          present paginate(controllers), with: Entities::Ci::RunnerController
        end

        desc 'Retrieve a single runner controller' do
          detail 'Retrieves details of a specified runner controller.'
          success Entities::Ci::RunnerControllerDetail
          failure [
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' }
          ]
          tags %w[runner_controllers]
        end
        params do
          requires :id, type: Integer, desc: 'ID of the runner controller.'
        end
        route_setting :lifecycle, :experiment
        route_setting :tier, :ultimate
        route_setting :authorization, permissions: :read_runner_controller, boundary_type: :instance,
          assignable_when: [:admin]
        get ':id' do
          controller = ::Ci::RunnerController.find_by_id(params[:id])

          if controller
            present controller, with: Entities::Ci::RunnerControllerDetail
          else
            not_found!
          end
        end

        desc 'Register a runner controller' do
          detail 'Registers a runner controller.'
          success Entities::Ci::RunnerController
          failure [
            { code: 403, message: 'Forbidden' },
            { code: 400, message: 'Bad Request' }
          ]
          tags %w[runner_controllers]
        end
        params do
          optional :description, type: String, desc: 'Description of the runner controller.',
            documentation: { example: 'Controller for managing runner' }
          optional :state, type: String, values: ::Ci::RunnerController.states.keys, default: 'disabled',
            desc: 'State of the runner controller.',
            documentation: { example: 'enabled' }
        end
        route_setting :lifecycle, :experiment
        route_setting :tier, :ultimate
        route_setting :authorization, permissions: :create_runner_controller, boundary_type: :instance,
          assignable_when: [:admin]
        post do
          result = ::Ci::RunnerControllers::CreateService.new(
            current_user: current_user,
            params: declared_params(include_missing: false).slice(:description, :state)
          ).execute

          render_api_error!(result.message, result.reason) unless result.success?

          present result.payload, with: Entities::Ci::RunnerController
        end

        desc 'Update a runner controller' do
          detail 'Updates the details of an existing runner controller by its ID.'
          success Entities::Ci::RunnerController
          failure [
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' },
            { code: 400, message: 'Bad Request' }
          ]
          tags %w[runner_controllers]
        end
        params do
          requires :id, type: Integer, desc: 'ID of the runner controller.'
          optional :description, type: String, desc: 'Description of the runner controller.',
            documentation: { example: 'Controller for managing runner' }
          optional :state, type: String, values: ::Ci::RunnerController.states.keys,
            desc: 'State of the runner controller.',
            documentation: { example: 'dry_run' }
        end
        route_setting :lifecycle, :experiment
        route_setting :tier, :ultimate
        route_setting :authorization, permissions: :update_runner_controller, boundary_type: :instance,
          assignable_when: [:admin]
        put ':id' do
          controller = ::Ci::RunnerController.find_by_id(params[:id])

          not_found! unless controller

          result = ::Ci::RunnerControllers::UpdateService.new(
            runner_controller: controller,
            current_user: current_user,
            params: declared_params(include_missing: false).slice(:description, :state)
          ).execute

          render_api_error!(result.message, result.reason) unless result.success?

          present result.payload, with: Entities::Ci::RunnerController
        end

        desc 'Delete a runner controller' do
          detail 'Deletes a specified runner controller. Administrators only.'
          success Entities::Ci::RunnerController
          failure [
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' }
          ]
          tags %w[runner_controllers]
        end
        params do
          requires :id, type: Integer, desc: 'ID of the runner controller.'
        end
        route_setting :lifecycle, :experiment
        route_setting :tier, :ultimate
        route_setting :authorization, permissions: :delete_runner_controller, boundary_type: :instance,
          assignable_when: [:admin]
        delete ':id' do
          controller = ::Ci::RunnerController.find_by_id(params[:id])

          not_found! unless controller

          destroy_conditionally!(controller) do
            result = ::Ci::RunnerControllers::DeleteService.new(
              runner_controller: controller,
              current_user: current_user
            ).execute

            render_api_error!(result.message, result.reason) unless result.success?
          end
        end
      end
    end
  end
end
