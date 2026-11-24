# frozen_string_literal: true

module Gitlab
  module Ai
    module Catalog
      module Skills
        # Where a Skill lives in a repository: `skills/<name>/SKILL.md`.
        #
        # One definition, because every caller encodes the same convention and each had spelled it
        # out. Discovery and the scaffolder build paths from the fragments; the merge request check
        # and the publish worker recognise paths with the regexp built from those same fragments,
        # so the two cannot describe different shapes. Two callers had already drifted into
        # different anchors before this existed.
        module Path
          ROOT = 'skills'
          FILENAME = 'SKILL.md'

          # \A and \z rather than ^ and $: a git path may contain a newline, and Ruby's ^ and $
          # match at line boundaries, so `^...$` would also match a path carrying a skill path on
          # its second line.
          REGEX = %r{\A#{ROOT}/[^/]+/#{Regexp.escape(FILENAME)}\z}
        end
      end
    end
  end
end
