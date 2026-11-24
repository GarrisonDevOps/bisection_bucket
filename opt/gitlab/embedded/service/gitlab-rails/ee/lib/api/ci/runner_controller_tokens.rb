# frozen_string_literal: true

module API
  module Ci
    class RunnerControllerTokens < ::API::Base
      include ::API::PaginationParams

      feature_category :continuous_integration

      before do
        authenticated_as_admin!

        not_found! unless ::License.feature_available?(:ci_runner_controllers)
      end

      resource :runner_controllers do
        route_setting :lifecycle, :experiment

        desc 'List all runner controller tokens' do
          detail 'Lists all runner controller tokens.'
          is_array true
          success Entities::Ci::RunnerControllerToken
          tags %w[runner_controller_tokens]
          failure [
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' }
          ]
        end
        params do
          requires :runner_controller_id, type: Integer, desc: 'ID of the runner controller.'
          use :pagination
        end
        route_setting :lifecycle, :experiment
        route_setting :tier, :ultimate
        route_setting :authorization, permissions: :read_runner_controller_token, boundary_type: :instance,
          assignable_when: [:admin]
        get ':runner_controller_id/tokens' do
          controller = ::Ci::RunnerController.find_by_id(params[:runner_controller_id])
          not_found! unless controller

          tokens = controller.tokens.active
          present paginate(tokens), with: Entities::Ci::RunnerControllerToken
        end

        desc 'Retrieve a single runner controller token' do
          detail 'Retrieves details of a specified runner controller token by its ID.'
          success Entities::Ci::RunnerControllerToken
          failure [
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' }
          ]
          tags %w[runner_controller_tokens]
        end
        params do
          requires :runner_controller_id, type: Integer, desc: 'ID of the runner controller.'
          requires :id, type: Integer, desc: 'ID of the runner controller token.'
        end
        route_setting :lifecycle, :experiment
        route_setting :tier, :ultimate
        route_setting :authorization, permissions: :read_runner_controller_token, boundary_type: :instance,
          assignable_when: [:admin]
        get ':runner_controller_id/tokens/:id' do
          controller = ::Ci::RunnerController.find_by_id(params[:runner_controller_id])
          not_found! unless controller

          token = controller.tokens.active.find_by_id(params[:id])
          if token
            present token, with: Entities::Ci::RunnerControllerToken
          else
            not_found!
          end
        end

        desc 'Create a runner controller token' do
          detail 'Creates a runner controller token.'
          success Entities::Ci::RunnerControllerTokenWithToken
          failure [
            { code: 403, message: 'Forbidden' },
            { code: 400, message: 'Bad Request' },
            { code: 404, message: 'Not found' }
          ]
          tags %w[runner_controller_tokens]
        end
        params do
          requires :runner_controller_id, type: Integer, desc: 'ID of the runner controller.'
          optional :description, type: String, desc: 'Description of the runner controller token.',
            documentation: { example: 'Token for managing runner' }
        end
        route_setting :lifecycle, :experiment
        route_setting :tier, :ultimate
        route_setting :authorization, permissions: :create_runner_controller_token, boundary_type: :instance,
          assignable_when: [:admin]
        post ':runner_controller_id/tokens' do
          controller = ::Ci::RunnerController.find_by_id(params[:runner_controller_id])
          not_found! unless controller

          result = ::Ci::RunnerControllers::CreateTokenService.new(
            runner_controller: controller,
            current_user: current_user,
            params: { description: params[:description] }
          ).execute

          render_api_error!(result.message, result.reason) unless result.success?

          present result.payload, with: Entities::Ci::RunnerControllerTokenWithToken
        end

        desc 'Revoke a runner controller token' do
          detail 'Revokes an existing runner controller token.'
          success code: 204
          failure [
            { code: 403, message: 'Forbidden' },
            { code: 400, message: 'Bad Request' },
            { code: 404, message: 'Not found' }
          ]
          tags %w[runner_controller_tokens]
        end
        params do
          requires :runner_controller_id, type: Integer, desc: 'ID of the runner controller.'
          requires :id, type: Integer, desc: 'ID of the runner controller token.'
        end
        route_setting :lifecycle, :experiment
        route_setting :tier, :ultimate
        route_setting :authorization, permissions: :revoke_runner_controller_token, boundary_type: :instance,
          assignable_when: [:admin]
        delete ':runner_controller_id/tokens/:id' do
          controller = ::Ci::RunnerController.find_by_id(params[:runner_controller_id])
          not_found! unless controller

          token = controller.tokens.active.find_by_id(params[:id])
          not_found! unless token

          result = ::Ci::RunnerControllers::RevokeTokenService.new(token:, current_user:).execute

          render_api_error!(result.message, result.reason) unless result.success?

          no_content!
        end

        desc 'Rotate a runner controller token' do
          detail 'Rotates an existing runner controller token.'
          success Entities::Ci::RunnerControllerTokenWithToken
          failure [
            { code: 403, message: 'Forbidden' },
            { code: 400, message: 'Bad Request' },
            { code: 404, message: 'Not found' }
          ]
          tags %w[runner_controller_tokens]
        end
        params do
          requires :runner_controller_id, type: Integer, desc: 'ID of the runner controller.'
          requires :id, type: Integer, desc: 'ID of the runner controller token.'
        end
        route_setting :lifecycle, :experiment
        route_setting :tier, :ultimate
        route_setting :authorization, permissions: :rotate_runner_controller_token, boundary_type: :instance,
          assignable_when: [:admin]
        post ':runner_controller_id/tokens/:id/rotate' do
          controller = ::Ci::RunnerController.find_by_id(params[:runner_controller_id])
          not_found! unless controller

          token = controller.tokens.active.find_by_id(params[:id])
          not_found! unless token

          response = ::Ci::RunnerControllers::RotateTokenService.new(
            token: token,
            current_user: current_user
          ).execute

          render_api_error!(response.message, response.reason) unless response.success?

          status :ok
          present response.payload, with: Entities::Ci::RunnerControllerTokenWithToken
        end
      end
    end
  end
end
