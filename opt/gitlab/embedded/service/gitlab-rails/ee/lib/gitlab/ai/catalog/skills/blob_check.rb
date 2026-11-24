# frozen_string_literal: true

module Gitlab
  module Ai
    module Catalog
      module Skills
        # Problems with the blob rather than its content. Kept apart from Validator so that
        # Validator stays free of repository concepts and can run against a plain string.
        module BlobCheck
          class << self
            # @param blob [Blob]
            # @return [Validator::Rejection, nil] nil when the blob can be read as a skill
            def rejection_for(blob)
              code, message = problem(blob)
              return unless code

              Validator::Rejection.new(path: blob.path, code: code, message: message, category: :platform)
            end

            private

            def problem(blob)
              if blob.stored_externally?
                [
                  :stored_in_lfs,
                  s_('AICatalogSkillValidation|The file is stored in Git LFS, which the AI Catalog cannot read.')
                ]
              elsif blob.truncated?
                [:file_too_large, s_('AICatalogSkillValidation|The file is too large to read.')]
              elsif blob.binary? || blob.data.nil? || !blob.data.valid_encoding?
                [:not_utf8_text, s_('AICatalogSkillValidation|The file is not UTF-8 text.')]
              end
            end
          end
        end
      end
    end
  end
end
