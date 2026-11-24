# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Create
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
              .and_then(AgentValidator.method(:validate))
              .and_then(DevfileFetcher.method(:fetch))
              .and_then(DevfileOperations::DevfileProcessor.method(:validate))
              .map(VolumeDefiner.method(:define))
              .map(ToolsInjectorComponentInserter.method(:insert))
              .map(MainComponentUpdater.method(:update))
              .map(ContainerCommandUpdater.method(:update))
              .map(InternalPoststartCommandsInserter.method(:insert))
              .map(VolumeComponentInserter.method(:insert))
              .and_then(Creator.method(:create))
              # NOTE: Gitlab::InternalEvents lazily sets various class-level state due to memoization, which would
              #       normally require us to set `enforce_immutability: false` on the `inspect_ok` and `inspect_err`
              #       calls, but in this ROP chain the memoization is already set as a side effect of calling
              #       Gitlab::InternalEvents in the model in a previous step, so we can still enforce immutability.
              .inspect_ok(WorkspaceObserver.method(:observe))
              .inspect_err(WorkspaceErrorsObserver.method(:observe))
              .and_then(WorkspaceSuccessfulResponseBuilder.method(:build))

          # rubocop:disable Lint/DuplicateBranch -- Rubocop doesn't know the branches are different due to destructuring
          case result
          in { err: WorkspaceCreateParamsValidationFailed => message }
            generate_error_response_from_message(message: message, reason: :bad_request)
          in { err: WorkspaceCreateDevfileLoadFailed => message }
            generate_error_response_from_message(message: message, reason: :bad_request)
          in { err: DevfileOperations::AllDevfileErrors => message }
            generate_error_response_from_message(message: message, reason: :bad_request)
          in { err: WorkspaceCreateFailed => message }
            generate_error_response_from_message(message: message, reason: :bad_request)
          in { ok: WorkspaceCreateSuccessful => message }
            { status: :success, payload: message.content }
          else
            raise Gitlab::Fp::UnmatchedResultError.new(result: result)
          end
          # rubocop:enable Lint/DuplicateBranch
        end
      end
    end
  end
end
