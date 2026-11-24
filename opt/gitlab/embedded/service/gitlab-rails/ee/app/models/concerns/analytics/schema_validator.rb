# frozen_string_literal: true

module Analytics
  module SchemaValidator
    def schema_errors_for(yaml)
      validator = JSONSchemer.schema(Pathname.new(Rails.root.join(self.class::SCHEMA_PATH)))
      validator_errors = validator.validate(yaml)
      validator_errors.map { |e| JSONSchemer::Errors.pretty(e) } if validator_errors.any?
    end
  end
end
