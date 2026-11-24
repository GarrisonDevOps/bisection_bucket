# frozen_string_literal: true

# This class extracts all references found in a piece
# it's either @name or email address or @@role

module Gitlab
  module CodeOwners
    class ReferenceExtractor
      # Not using `Devise.email_regexp` to filter out any chars that an email
      # does not end with and not pinning the email to a start of end of a string.
      EMAIL_REGEXP = /[^@\s]{1,100}@[^@\s]{1,255}(?<!\W)/

      # Pattern used to extract `@user` user references from text.
      # This has a small modification from User.reference_pattern as code owners
      # excludes references prefixed with @@.
      NAME_REGEXP =
        %r{
          (?<![\w@])
          #{Regexp.escape(User.reference_prefix)}
          (?<user>#{Gitlab::PathRegex::FULL_NAMESPACE_FORMAT_REGEX})
        }x

      ROLES_MAP = {
        'developer' => Gitlab::Access::DEVELOPER,
        'maintainer' => Gitlab::Access::MAINTAINER,
        'owner' => Gitlab::Access::OWNER
      }.freeze

      ROLE_PREFIX = '@@'

      ROLE_REGEXP = %r{(?<![\w@])#{ROLE_PREFIX}(?<role>(#{Regexp.union(ROLES_MAP.keys).source})s?)(?:\s|$)}i

      def initialize(text)
        # EE passes an Array to `text` in a few places, so we want to support both
        # here.
        @text = Array(text).join(' ')
      end

      def names
        matches[:names]
      end

      def raw_names
        names.map { |name| "@#{name}" }
      end

      def roles
        matches[:roles].map { |role| ROLES_MAP[role.singularize.downcase] }.uniq
      end

      def raw_roles
        matches[:roles].map { |role| "#{ROLE_PREFIX}#{role}" }
      end

      def emails
        matches[:emails]
      end

      alias_method :raw_emails, :emails

      def references
        return [] if @text.blank?

        @references ||= names + roles + emails
      end

      def raw_references
        return [] if @text.blank?

        @raw_references ||= raw_names + raw_roles + raw_emails
      end

      private

      def matches
        @matches ||= {
          emails: @text.scan(EMAIL_REGEXP).flatten.uniq,
          names: @text.scan(NAME_REGEXP).flatten.uniq,
          roles: @text.scan(ROLE_REGEXP).flatten.uniq
        }
      end
    end
  end
end
