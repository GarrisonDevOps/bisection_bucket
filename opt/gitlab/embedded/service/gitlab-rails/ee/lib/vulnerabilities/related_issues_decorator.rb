# frozen_string_literal: true

module Vulnerabilities
  class RelatedIssuesDecorator < SimpleDelegator
    attr_reader :vulnerability_link

    def set_vulnerability_link(vulnerability_link)
      @vulnerability_link = vulnerability_link
    end

    def vulnerability_link_id
      vulnerability_link.id
    end

    def vulnerability_link_type
      vulnerability_link.link_type
    end
  end
end
