# frozen_string_literal: true

module Gitlab
  module BackgroundMigration
    # Decodes HTML entities, e.g. `&amp;`, that legacy sanitization stored in user_details.
    # Sanitizable rejects these values, see https://gitlab.com/gitlab-org/gitlab/-/work_items/583966.
    class CleanupUserDetailHtmlEntities < BatchedMigrationJob
      cursor :user_id
      operation_name :cleanup_user_detail_html_entities
      feature_category :user_profile

      COLUMNS = %w[bluesky discord linkedin mastodon orcid twitter website_url github].freeze
      ENTITY_PATTERN = '&(#[0-9]+|#[xX][0-9a-fA-F]+|[a-zA-Z]+);'
      MAX_DECODE_PASSES = 5
      URL_SCHEME = /\A[a-z][a-z0-9+.-]*:/i
      HTTP_SCHEME = %r{\Ahttps?://}i

      def perform
        each_sub_batch do |sub_batch|
          candidates(sub_batch).each do |row|
            COLUMNS.each do |column|
              old_value = row[column]
              new_value = decode(old_value)
              next if new_value == old_value

              reason = skip_reason(column, new_value)

              if reason
                log_skip(row.user_id, column, reason)
              else
                # The old value guard keeps a concurrent profile edit from being overwritten.
                sub_batch.klass.where(user_id: row.user_id, column => old_value).update_all(column => new_value)
              end
            end
          end
        end
      end

      private

      def candidates(sub_batch)
        condition = COLUMNS.map { |column| "#{column} ~ :pattern" }.join(' OR ')

        # A cursor sub-batch applies its LIMIT last, so filter in a derived table to keep the filter inside it.
        sub_batch.klass.from(sub_batch.select(:user_id, *COLUMNS), :user_details).where(condition,
          pattern: ENTITY_PATTERN)
      end

      # Repeats the Sanitizable.sanitize steps until stable, so a profile save keeps the result.
      # Unsafe characters return early for skip_reason, because Sanitize.fragment would drop them silently.
      def decode(value)
        return value if value == CGI.unescapeHTML(value)

        MAX_DECODE_PASSES.times do
          decoded = CGI.unescapeHTML(value)
          return decoded if !decoded.valid_encoding? || decoded.match?(/[[:cntrl:]]/)

          decoded = CGI.unescapeHTML(Sanitize.fragment(decoded))
          return value if decoded == value

          value = decoded
        end

        value
      end

      def skip_reason(column, value)
        return 'invalid_encoding' unless value.valid_encoding?
        return 'control_character' if value.match?(/[[:cntrl:]]/)
        return 'escaped_html_entities' if value != CGI.unescapeHTML(value)
        # update_all bypasses the `url: true` validation, which only accepts http and https.
        return 'invalid_url_scheme' if column == 'website_url' && value.match?(URL_SCHEME) && !value.match?(HTTP_SCHEME)

        # Mirrors Gitlab::PathTraversal.check_path_traversal!, which raises and logs the value.
        url_decoded = CGI.unescape(value)
        return 'invalid_encoding' unless url_decoded.valid_encoding?
        return 'double_encoding' if url_decoded != CGI.unescape(url_decoded)
        return 'path_traversal' if Gitlab::PathTraversal.path_traversal?(url_decoded)

        nil
      end

      def log_skip(user_id, column, reason)
        ::Gitlab::BackgroundMigration::Logger.warn(
          :message => 'CleanupUserDetailHtmlEntities skipped value',
          Labkit::Fields::GL_USER_ID => user_id,
          :column => column,
          :skip_reason => reason
        )
      end
    end
  end
end
