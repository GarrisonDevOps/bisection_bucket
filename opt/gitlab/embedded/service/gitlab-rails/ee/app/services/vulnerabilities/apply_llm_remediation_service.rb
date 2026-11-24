# frozen_string_literal: true

module Vulnerabilities
  class ApplyLlmRemediationService
    private attr_reader :new_code, :old_code, :source_content

    def initialize(old_code, new_code, source_content)
      @old_code = old_code
      @new_code = new_code
      @source_content = source_content
    end

    def execute
      # a `blank?` new_code is valid, so we use nil?
      return error('No new code to apply to source') if new_code.nil?
      return error('No original code to match against') if old_code.blank?
      return error('No source code to match on') if source_content.blank?

      patched_content = source_content.gsub(old_code, new_code)
      ServiceResponse.success(payload: { patched_content: patched_content })
    rescue StandardError => e
      ServiceResponse.error(message: "Unexpected error while patching the source", payload: { exception: e })
    end

    private

    def error(message)
      ServiceResponse.error(message: message)
    end
  end
end
