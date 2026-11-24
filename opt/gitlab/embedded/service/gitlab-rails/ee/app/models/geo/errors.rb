# frozen_string_literal: true

module Geo
  module Errors
    BaseError = Class.new(StandardError)

    class StatusTimeoutError < BaseError
      def message
        "Generating Geo node status is taking too long"
      end
    end

    class UnknownSelectiveSyncType < BaseError
      attr_reader :selective_sync_type

      def initialize(selective_sync_type:)
        @selective_sync_type = selective_sync_type
      end

      def message
        "Selective sync type is not known: #{selective_sync_type}"
      end
    end

    class ReplicableExcludedFromVerificationError < BaseError
      attr_reader :model_class, :model_record_id

      def initialize(model_class:, model_record_id:)
        @model_class = model_class
        @model_record_id = model_record_id

        Gitlab::Geo::Logger.warn(
          message: "File is not checksummable because the replicable is excluded from verification",
          model_class: model_class,
          model_record_id: model_record_id
        )
      end

      def message
        "File is not checksummable - #{model_class} #{model_record_id} is excluded from verification"
      end
    end

    class ReplicableDoesNotExistError < BaseError
      attr_reader :file_path

      def initialize(file_path:)
        @file_path = file_path

        Gitlab::Geo::Logger.warn(
          message: "File is not checksummable because it does not exist",
          file_path: file_path
        )
      end

      def message
        MessageWithFilePath.build(
          prefix: "File is not checksummable - file does not exist at: ",
          file_path: file_path
        )
      end
    end

    OrgMigrationRepositoryStorageNotReadyError = Class.new(BaseError)
  end
end
