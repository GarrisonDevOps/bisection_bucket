# frozen_string_literal: true

module Search
  module Zoekt
    class CodeQueryBuilder < QueryBuilder
      # `language` is a public GraphQL argument, so values can contain arbitrary characters even though
      # the UI only sends linguist-detected names. Quote and escape any value containing characters that
      # Zoekt's atom parser treats as significant (whitespace, quotes, parentheses, backslash) so the
      # resulting `lang:` atom cannot break out into other query operators.
      ZOEKT_LANG_UNSAFE_RE = /[\s"\\()]/

      def build
        build_payload
      end

      private

      def build_payload
        auth = Search::AuthorizationContext.new(current_user)

        base_query = Filters.by_query_string(apply_language_filter(query))
        return build_repo_ids_payload(base_query) unless use_zoekt_traversal_id_query?

        children = [base_query]

        # IMPORTANT: Scoping filters (repo_ids/traversal_ids) must come immediately after query_string.
        # Placing meta filters (like archived) between query_string and scoping filters causes
        # significant performance regression (see https://gitlab.com/gitlab-org/gitlab/-/issues/586416).
        case options.fetch(:search_level)
        when :project
          raise ArgumentError, 'Project ID cannot be empty for project search' if project_id.blank?

          children << Filters.by_repo_ids([project_id], context: { name: 'project_id_search' })
        when :group
          children << Filters.by_traversal_ids(
            auth.get_traversal_ids_for_group(group_id),
            context: { name: 'traversal_ids_for_group' }
          )
        when :global
          # no additional filters needed
        else
          raise ArgumentError, "Unsupported search level for zoekt search: #{options.fetch(:search_level)}"
        end

        children << Filters.by_archived(false) unless filters[:include_archived] == true
        children << Filters.by_forked(false) unless filters[:exclude_forks] == false

        # Add access branch filters at the very end because they are more expensive to evaluate.
        children << Filters.or_filters(*access_branches(auth), context: { name: 'access_branches' })

        Filters.and_filters(*children)
      end

      def build_repo_ids_payload(base_query)
        raise ArgumentError, 'Repo ids cannot be empty' if options[:repo_ids].blank?

        Filters.and_filters(base_query, Filters.by_repo_ids(options[:repo_ids]))
      end

      def access_branches(auth)
        @access_branches ||= AccessBranchBuilder.new(current_user, auth, options).build
      end

      def use_zoekt_traversal_id_query?
        options.fetch(:use_traversal_id_queries)
      end

      def apply_language_filter(query_string)
        languages = Array(filters[:language]).compact_blank
        return query_string if languages.empty?

        named, unknown = languages.partition { |lang| lang != ::Search::Zoekt::SearchResults::UNKNOWN_LANGUAGE }

        atoms = named.map { |lang| "lang:#{quote_language(lang)}" }
        atoms << unknown_atom if unknown.any?
        atoms.compact!

        return query_string if atoms.empty?

        clause = atoms.length == 1 ? atoms.first : "(#{atoms.join(' or ')})"

        "#{query_string} #{clause}"
      end

      # Nil without a known-language list: the complement cannot be expressed, and a literal
      # lang:Unknown matches nothing in Zoekt, so the caller drops the filter instead of
      # returning an empty page the user cannot recover from.
      def unknown_atom
        known = Array(options[:known_languages]).compact_blank
        return if known.empty?

        "(#{known.map { |lang| "-lang:#{quote_language(lang)}" }.join(' ')})"
      end

      def quote_language(lang)
        return lang unless lang.match?(ZOEKT_LANG_UNSAFE_RE)

        escaped = lang.gsub(/([\\"])/) { |c| "\\#{c}" }
        %("#{escaped}")
      end
    end
  end
end
