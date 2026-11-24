# frozen_string_literal: true

module Geo
  # This class matches a name with a URL, in order to determine if the name could be missing a trailing slash.
  # In the past, Geo has been using GeoNode URL and more recently name as unique identifiers
  # for a Geo Site. Trailing slashes to URLs and name field have caused bugs leading to this class
  # that handles comparison, addition and deletion of missing or extra trailing slashes.
  class NodeNameSanitizer
    attr_reader :name, :url

    def initialize(name:, url: '')
      @name = name
      @url = url
    end

    def match?(value)
      return true if name == value
      return name.chomp('/') == value.chomp('/') if both_have_ending_slashes? || match_if_name_has_a_slash?

      false
    end

    def sanitized_name
      return name_with_slash if match_if_name_has_a_slash? || none_have_ending_slashes?
      return name_without_slash if match_if_name_has_no_slash? || both_have_ending_slashes?

      name
    end

    def name_without_slash
      return name if name.blank?

      name.chomp('/')
    end

    def name_with_slash
      return name if name.blank?
      return name if name_ends_with_slash?

      "#{name}/"
    end

    private

    def match_if_name_has_a_slash?
      return false if url.blank?
      return false unless url_ends_with_slash?
      return false if name_ends_with_slash?

      name_with_slash == url
    end

    def match_if_name_has_no_slash?
      return false if name.blank?
      return false unless name_ends_with_slash?
      return false if url_ends_with_slash?

      name_without_slash == url
    end

    def both_have_ending_slashes?
      name == url && name_ends_with_slash? && url_ends_with_slash?
    end

    def none_have_ending_slashes?
      name == url && !name_ends_with_slash? && !url_ends_with_slash?
    end

    def name_ends_with_slash?
      name.end_with?('/')
    end

    def url_ends_with_slash?
      url.end_with?('/')
    end
  end
end
