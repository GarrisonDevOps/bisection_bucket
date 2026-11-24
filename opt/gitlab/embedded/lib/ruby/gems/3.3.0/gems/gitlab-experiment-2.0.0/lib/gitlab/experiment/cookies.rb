# frozen_string_literal: true

module Gitlab
  class Experiment
    module Cookies
      private

      def migrate_cookie(hash, cookie_name)
        return hash if cookie_jar.nil?

        resolver = [hash, :actor, cookie_name, cookie_jar.signed[cookie_name]]
        resolve_cookie(*resolver) || generate_cookie(*resolver)
      end

      def cookie_jar
        @request&.cookie_jar
      end

      def resolve_cookie(hash, key, cookie_name, cookie)
        return if cookie.to_s.empty? && hash[key].nil?
        return hash if cookie.to_s.empty?
        return hash.merge(key => cookie) if hash[key].nil?

        add_unmerged_migration(key => cookie)
        cookie_jar.delete(cookie_name, domain:)

        hash
      end

      def generate_cookie(hash, key, cookie_name, cookie)
        return hash unless hash.key?(key)

        cookie ||= SecureRandom.uuid
        cookie_jar.permanent.signed[cookie_name] = {
          value: cookie, secure: Configuration.secure_cookie, domain:, httponly: true
        }

        hash.merge(key => cookie)
      end

      def domain
        Configuration.cookie_domain
      end
    end
  end
end
