# frozen_string_literal: true

module Ai
  module ActiveContext
    module Queries
      class Result
        include Enumerable

        NilHitsError = Class.new(StandardError)

        attr_reader :success, :hits, :error_code, :error_detail
        alias_method :success?, :success

        ERROR_NO_EMBEDDINGS = :no_embeddings

        ERROR_MESSAGE_TEMPLATE = {
          ERROR_NO_EMBEDDINGS => "%{target_class} '%{target_id}' has no embeddings"
        }.freeze

        def self.success(hits)
          new(success: true, hits: hits)
        end

        def self.error(error_code, error_detail: nil)
          new(success: false, error_code: error_code, error_detail: error_detail)
        end

        def self.no_embeddings_error(error_detail: nil)
          error(ERROR_NO_EMBEDDINGS, error_detail: error_detail)
        end

        def initialize(success:, hits: nil, error_code: nil, error_detail: nil)
          @success = success == true
          @hits = hits
          @error_code = error_code
          @error_detail = error_detail
        end

        def error_message(target_class:, target_id:)
          return unknown_error_message unless error_code && ERROR_MESSAGE_TEMPLATE.key?(error_code)

          message = format(
            ERROR_MESSAGE_TEMPLATE[error_code],
            target_class: target_class,
            target_id: target_id
          )
          message += " - #{error_detail}" if error_detail

          message
        end

        def each(&block)
          unless hits
            raise(
              NilHitsError,
              "`hits` is nil. This is likely a failure result, please check `success?`"
            )
          end

          hits.each(&block)
        end

        # privatize the `success` getter so `success?` will always be used
        private :success

        private

        def unknown_error_message
          error_detail || "Unknown error"
        end
      end
    end
  end
end
