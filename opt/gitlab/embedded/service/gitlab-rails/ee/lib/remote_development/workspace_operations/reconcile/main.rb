# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Reconcile
      class Main
        include Messages
        extend Gitlab::Fp::MessageSupport

        # @param [Hash] context
        # @return [Hash]
        # @raise [Gitlab::Fp::UnmatchedResultError]
        def self.main(context)
          initial_result = Gitlab::Fp::Result.ok(context)

          result =
            initial_result
              .and_then(Input::ParamsValidator.method(:validate))
              .map(Input::ParamsExtractor.method(:extract))
              .map(Input::ParamsToInfosConverter.method(:convert))
              .inspect_ok(Input::AgentInfosObserver.method(:observe))
              .map(Persistence::WorkspacesFromAgentInfosUpdater.method(:update))
              .inspect_ok(Persistence::OrphanedWorkspacesObserver.method(:observe))
              .map(Persistence::WorkspacesLifecycleManager.method(:manage))
              .map(Persistence::WorkspacesToBeReturnedFinder.method(:find))
              .map(Output::ResponsePayloadBuilder.method(:build))
              .map(Persistence::WorkspacesToBeReturnedUpdater.method(:update))
              .inspect_ok(Output::ResponsePayloadObserver.method(:observe))
              .map(
                # As the final step, return the response_payload content in a WorkspaceReconcileSuccessful message
                ->(context) do
                  WorkspaceReconcileSuccessful.new(context.fetch(:response_payload))
                end
              )

          case result
          in { err: WorkspaceReconcileParamsValidationFailed => message }
            generate_error_response_from_message(message: message, reason: :bad_request)
          in { ok: WorkspaceReconcileSuccessful => message }
            # Type-check the payload before returning it
            message.content => {
              workspace_rails_infos: Array,
              settings: Hash
            }
            { status: :success, payload: message.content }
          else
            raise Gitlab::Fp::UnmatchedResultError.new(result: result)
          end
        end
      end
    end
  end
end
