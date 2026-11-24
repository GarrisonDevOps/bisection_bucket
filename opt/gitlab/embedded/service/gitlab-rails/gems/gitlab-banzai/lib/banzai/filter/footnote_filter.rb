# frozen_string_literal: true

module Banzai
  module Filter
    # HTML Filter for footnotes
    #
    # Footnotes are supported in CommonMark.  However we were stripping
    # the ids during sanitization.  Those are now allowed.
    #
    # Footnotes are numbered as an increasing integer starting at `1`.
    # The `id` associated with a footnote is based on the footnote reference
    # string.  For example, `[^foot]` will generate `id="fn-foot"`.
    # In order to allow footnotes when rendering multiple markdown blocks
    # on a page, we need to make each footnote reference unique.

    # This filter adds a random number to each footnote (the same number
    # can be used for a single render). So you get `id=fn-1-4335` and `id=fn-foot-4335`.
    #
    class FootnoteFilter < HTML::Pipeline::Filter
      prepend Concerns::PipelineTimingCheck

      FOOTNOTE_ID_PREFIX              = 'fn-'
      FOOTNOTE_LINK_ID_PREFIX         = 'fnref-'
      FOOTNOTE_LINK_HREF_PREFIX       = "##{FOOTNOTE_ID_PREFIX}".freeze
      FOOTNOTE_LI_REFERENCE_PATTERN   = /\A#{FOOTNOTE_ID_PREFIX}.+\z/
      FOOTNOTE_LINK_REFERENCE_PATTERN = /\A#{FOOTNOTE_LINK_ID_PREFIX}.+\z/

      CSS_SECTION    = "section[data-footnotes]"
      XPATH_SECTION  = Gitlab::Utils::Nokogiri.css_to_xpath(CSS_SECTION).freeze
      CSS_FOOTNOTE   = 'sup > a[data-footnote-ref]'
      XPATH_FOOTNOTE = Gitlab::Utils::Nokogiri.css_to_xpath(CSS_FOOTNOTE).freeze

      CSS_FOOTNOTE_ITEM   = 'section[data-footnotes] li[id]'
      XPATH_FOOTNOTE_ITEM = Gitlab::Utils::Nokogiri.css_to_xpath(CSS_FOOTNOTE_ITEM).freeze
      CSS_BACKREF         = 'a[data-footnote-backref]'
      XPATH_BACKREF       = Gitlab::Utils::Nokogiri.css_to_xpath(CSS_BACKREF).freeze

      # Limit of how many footnotes we will process.
      # Protects against pathological number of footnotes.
      FOOTNOTE_LIMIT = 1000

      def call
        # Sanitization stripped off the section class - add it back in
        return doc if doc.xpath(XPATH_FOOTNOTE).count > 1000
        return doc unless section_node = doc.at_xpath(XPATH_SECTION)

        section_node.append_class('footnotes')

        rand_suffix = "-#{random_number}"
        footnote_nodes = doc.xpath(XPATH_FOOTNOTE_ITEM).each_with_object({}) do |node, nodes|
          nodes[node[:id]] ||= node
        end
        modified_footnotes = {}

        doc.xpath(XPATH_FOOTNOTE).each do |link_node|
          next unless link_node[:id] && link_node[:href]&.start_with?(FOOTNOTE_LINK_HREF_PREFIX)

          # Take the footnote from the href, not the id: the second reference to
          # `[^1]` has the id `fnref-1-2` but still links to `#fn-1`.
          footnote_node_id = link_node[:href].delete_prefix('#')
          backref_nodes = modified_footnotes[footnote_node_id] ||=
            modify_footnote(footnote_nodes[footnote_node_id], rand_suffix)
          next unless backref_nodes

          backref_node = backref_nodes.delete("##{link_node[:id]}")

          link_node[:href] += rand_suffix
          link_node[:id]   += rand_suffix

          # Sanitization stripped off class - add it back in
          link_node.parent.append_class('footnote-ref')

          next unless backref_node

          backref_node[:href] += rand_suffix

          footnote_id = backref_node['data-footnote-backref-idx']
          backref_node[:title] = Banzai.configuration.translate(:footnote_backref_title, footnote_id: footnote_id)
          backref_node['aria-label'] = backref_node[:title]
          backref_node.append_class('footnote-backref')
        end

        doc
      end

      private

      # Adds the suffix to the id of the footnote and returns its back-references
      # by href, or nil when the document has no such footnote.
      def modify_footnote(footnote_node, rand_suffix)
        return unless footnote_node

        footnote_node[:id] += rand_suffix
        footnote_node.xpath(XPATH_BACKREF).index_by { |backref_node| backref_node[:href] }
      end

      def random_number
        # We allow overriding the randomness with a static value from GITLAB_TEST_FOOTNOTE_ID.
        # This allows stable generation of example HTML during GLFM Snapshot Testing
        # (https://docs.gitlab.com/ee/development/gitlab_flavored_markdown/specification_guide/#markdown-snapshot-testing),
        # and reduces the need for normalization of the example HTML
        # (https://docs.gitlab.com/ee/development/gitlab_flavored_markdown/specification_guide/#normalization)
        @random_number ||= ENV.fetch('GITLAB_TEST_FOOTNOTE_ID', rand(10000))
      end
    end
  end
end
