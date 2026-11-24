# frozen_string_literal: true

require 'uri'

module Banzai
  module Filter
    # HTML filter that converts relative documentation urls into absolute ones.
    class AbsoluteDocumentationLinkFilter < Banzai::Filter::AbsoluteLinkFilter
      extend ::Gitlab::Utils::Override

      CSS = 'a'
      XPATH = Gitlab::Utils::Nokogiri.css_to_xpath(CSS).freeze

      protected

      override :skip?
      def skip?
        context[:base_url].blank?
      end

      override :convert_link_href
      def convert_link_href(uri)
        path = URI.join(context[:base_url], uri).path.gsub('.md', '.html')

        URI.join(Gitlab.config.gitlab.url, path).to_s
      end
    end
  end
end
