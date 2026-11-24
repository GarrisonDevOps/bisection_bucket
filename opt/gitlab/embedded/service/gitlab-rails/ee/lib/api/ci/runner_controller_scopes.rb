# frozen_string_literal: true

module API
  module Ci
    class RunnerControllerScopes < ::API::Base
      feature_category :continuous_integration

      before do
        authenticated_as_admin!

        not_found! unless ::License.feature_available?(:ci_runner_controllers)
      end

      helpers do
        def find_runner_controller!
          ::Ci::RunnerController.find(params[:id])
        end

        def find_runner!(runner_id)
          ::Ci::Runner.find(runner_id)
        end
      end

      resource :runner_controllers do
        route_setting :lifecycle, :experiment

        desc 'List all scopes for a runner controller' do
          detail 'Lists all scopes for a runner controller.'
          success code: 200
          tags %w[runner_controllers]
          failure [
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' }
          ]
        end
        params do
          requires :id, type: Integer, desc: 'ID of the runner controller.'
        end
        route_setting :tier, :ultimate
        route_setting :authorization, permissions: :read_runner_controller, boundary_type: :instance,
          assignable_when: [:admin]
        get ':id/scopes' do
          controller = find_runner_controller!

          instance_level_scopings = [controller.instance_level_scoping].compact
          runner_level_scopings = controller.runner_level_scopings

          {
            instance_level_scopings: instance_level_scopings.map do |scoping|
              Entities::Ci::RunnerControllerInstanceLevelScoping.represent(scoping)
            end,
            runner_level_scopings: runner_level_scopings.map do |scoping|
              Entities::Ci::RunnerControllerRunnerLevelScoping.represent(scoping)
            end
          }
        end

        desc 'Add instance scope' do
          detail 'Adds an instance scope to a runner controller. When added, the runner controller evaluates jobs ' \
            'for all runners in the GitLab instance. A runner controller can have only one instance scope. If an ' \
            'instance scope already exists, this operation returns an error.'
          success Entities::Ci::RunnerControllerInstanceLevelScoping
          tags %w[runner_controllers]
          failure [
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' },
            { code: 409, message: 'Conflict' }
          ]
        end
        params do
          requires :id, type: Integer, desc: 'ID of the runner controller.'
        end
        route_setting :tier, :ultimate
        route_setting :authorization, permissions: :update_runner_controller, boundary_type: :instance,
          assignable_when: [:admin]
        post ':id/scopes/instance' do
          controller = find_runner_controller!

          result = ::Ci::RunnerControllers::Scopes::AddInstanceService.new(
            runner_controller: controller,
            current_user: current_user
          ).execute

          render_api_error!(result.message, result.reason) unless result.success?

          present result.payload, with: Entities::Ci::RunnerControllerInstanceLevelScoping
        end

        desc 'Remove instance scope' do
          detail 'Removes an instance scope from a runner controller.'
          success code: 204
          tags %w[runner_controllers]
          failure [
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' }
          ]
        end
        params do
          requires :id, type: Integer, desc: 'ID of the runner controller.'
        end
        route_setting :tier, :ultimate
        route_setting :authorization, permissions: :update_runner_controller, boundary_type: :instance,
          assignable_when: [:admin]
        delete ':id/scopes/instance' do
          controller = find_runner_controller!

          result = ::Ci::RunnerControllers::Scopes::RemoveInstanceService.new(
            runner_controller: controller,
            current_user: current_user
          ).execute

          render_api_error!(result.message, result.reason) unless result.success?

          no_content!
        end

        desc 'Add runner scope' do
          detail 'Adds a runner scope to a runner controller. When added, the runner controller evaluates jobs only ' \
            'for a specified runner. A runner controller with an instance scope cannot have runner scopes. Remove ' \
            'the instance scope before adding runner scopes. This feature was introduced in GitLab 18.10.'
          success Entities::Ci::RunnerControllerRunnerLevelScoping
          tags %w[runner_controllers]
          failure [
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' },
            { code: 409, message: 'Conflict' },
            { code: 422, message: 'Unprocessable Entity' }
          ]
        end
        params do
          requires :id, type: Integer, desc: 'ID of the runner controller.'
          requires :runner_id, type: Integer, desc: 'ID of the runner. Must be an instance runner.'
        end
        route_setting :tier, :ultimate
        route_setting :authorization, permissions: :update_runner_controller, boundary_type: :instance,
          assignable_when: [:admin]
        post ':id/scopes/runners/:runner_id' do
          controller = find_runner_controller!
          runner = find_runner!(params[:runner_id])

          result = ::Ci::RunnerControllers::Scopes::AddRunnerService.new(
            runner_controller: controller,
            runner: runner,
            current_user: current_user
          ).execute

          render_api_error!(result.message, result.reason) unless result.success?

          present result.payload, with: Entities::Ci::RunnerControllerRunnerLevelScoping
        end

        desc 'Remove runner scope' do
          detail 'Removes a runner scope from a runner controller. This feature was introduced in GitLab 18.10.'
          success code: 204
          tags %w[runner_controllers]
          failure [
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' }
          ]
        end
        params do
          requires :id, type: Integer, desc: 'ID of the runner controller.'
          requires :runner_id, type: Integer, desc: 'ID of the runner.'
        end
        route_setting :tier, :ultimate
        route_setting :authorization, permissions: :update_runner_controller, boundary_type: :instance,
          assignable_when: [:admin]
        delete ':id/scopes/runners/:runner_id' do
          controller = find_runner_controller!
          runner = find_runner!(params[:runner_id])

          result = ::Ci::RunnerControllers::Scopes::RemoveRunnerService.new(
            runner_controller: controller,
            runner: runner,
            current_user: current_user
          ).execute

          render_api_error!(result.message, result.reason) unless result.success?

          no_content!
        end
      end
    end
  end
end
