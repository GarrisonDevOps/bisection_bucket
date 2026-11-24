# frozen_string_literal: true

module Sbom
  module ExportSerializers
    class JsonService
      def initialize(report)
        @report = report
      end

      def execute
        json_entity = Sbom::SbomEntity.represent(report)
        schema_validator = Gitlab::Ci::Parsers::Sbom::Validators::CyclonedxSchemaValidator.new(
          json_entity.as_json.with_indifferent_access
        )

        if schema_validator.valid?
          ServiceResponse.success(payload: json_entity)
        else
          ServiceResponse.error(
            message: schema_validator.errors,
            payload: json_entity,
            reason: :schema_invalid
          )
        end
      end

      private

      attr_reader :report
    end
  end
end
