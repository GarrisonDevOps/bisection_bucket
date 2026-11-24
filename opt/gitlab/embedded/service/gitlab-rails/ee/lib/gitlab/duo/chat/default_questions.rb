# frozen_string_literal: true

module Gitlab
  module Duo
    module Chat
      class DefaultQuestions
        include ::Gitlab::Utils::StrongMemoize

        SUPPORTED_CONTEXT = [
          :code, :issue, :epic, :merge_request, :commit, :ci_build, :wiki
        ].freeze

        DEFAULT = [
          "How can I improve my code security?",
          "What are code review best practices?",
          "Help me set up continuous deployment",
          "Show me automated testing strategies",
          "How can I organize projects effectively in GitLab?",
          "How do I manage environment variables?",
          "What causes pipeline failures?",
          "How do I securely store secrets in GitLab CI/CD?",
          "How do I scan dependencies for vulnerabilities?",
          "How do I make my CI pipelines run faster?",
          "How do I debug issues with GitLab runners?",
          "How do I set up quality gates in my pipeline?",
          "How should I structure complex epics?",
          "What makes good acceptance criteria?",
          "How do I estimate story points?"
        ].freeze

        # Page-specific: these read as questions about the blob currently on
        # screen, so they only ever surface through the contextual category.
        # The static `development` category carries the generic ones instead.
        CODE = [
          "What does this code do?",
          "How can I make this code more efficient?",
          "Identify any security vulnerabilities in my code",
          "Are there any bugs in this code?",
          "Create documentation for this code"
        ].freeze

        WIKI = [
          "What is this wiki page about?",
          "What discussions exist on this page?",
          "How do I create a new wiki page?",
          "How can I create a wiki page template?",
          "Where can I see page version history?",
          "How do I customize the wiki sidebar?"
        ].freeze

        # Ordered by observed usage and drawn from the topic categories
        # below, so repeats between the two lists are expected.
        GET_STARTED = [
          "What causes pipeline failures?",
          "How do I securely store secrets in GitLab CI/CD?",
          "How do I make my CI pipelines run faster?",
          "What are code review best practices?",
          "How can I organize projects effectively in GitLab?"
        ].freeze

        DEVELOPMENT = [
          "Show me automated testing strategies",
          "What are code review best practices?",
          "How can I improve my code security?"
        ].freeze

        WORK_ITEMS = [
          "How should I structure complex epics?",
          "What makes good acceptance criteria?",
          "How do I estimate story points?",
          "Summarize my open issues in this project"
        ].freeze

        MERGE_REQUESTS = [
          "What are code review best practices?",
          "Summarize my open merge requests",
          "Which of my merge requests are waiting on review?",
          "Help me write a merge request description"
        ].freeze

        PIPELINES = [
          "Help me set up continuous deployment",
          "How do I manage environment variables?",
          "What causes pipeline failures?",
          "How do I make my CI pipelines run faster?",
          "How do I debug issues with GitLab runners?",
          "How do I securely store secrets in GitLab CI/CD?"
        ].freeze

        SECURITY = [
          "How can I improve my code security?",
          "How do I scan dependencies for vulnerabilities?",
          "How do I set up quality gates in my pipeline?",
          "What security scanners does GitLab provide?"
        ].freeze

        # Titles are lambdas so `s_` runs per request, under the caller's
        # locale, rather than once at class load.
        STATIC_CATEGORIES = [
          { key: 'get_started', title: -> { s_('DuoAgenticChat|Get started') }, questions: GET_STARTED },
          { key: 'development', title: -> { s_('DuoAgenticChat|Development') }, questions: DEVELOPMENT },
          { key: 'work_items', title: -> { s_('DuoAgenticChat|Work items') }, questions: WORK_ITEMS },
          { key: 'merge_requests', title: -> { s_('DuoAgenticChat|Merge requests') }, questions: MERGE_REQUESTS },
          { key: 'pipelines', title: -> { s_('DuoAgenticChat|Pipelines') }, questions: PIPELINES },
          { key: 'security', title: -> { s_('DuoAgenticChat|Security') }, questions: SECURITY }
        ].freeze

        # Fallback for a context that has no reference of its own to show.
        DEFAULT_CONTEXTUAL_TITLE = -> { s_('DuoAgenticChat|This page') }

        # Page-specific lists keyed by the controller serving the page. The
        # value's `key` doubles as the contextual category key sent to clients.
        PAGE_TYPES = {
          'projects/blob' => { key: 'blob', title: -> { s_('DuoAgenticChat|This file') }, questions: CODE },
          'projects/wikis' => { key: 'wiki', title: DEFAULT_CONTEXTUAL_TITLE, questions: WIKI },
          'groups/wikis' => { key: 'wiki', title: DEFAULT_CONTEXTUAL_TITLE, questions: WIKI }
        }.freeze

        # Ci::Build serves no page of its own, so its title cannot live in
        # PAGE_TYPES alongside the rest.
        RESOURCE_TITLES = {
          'build' => -> { s_('DuoAgenticChat|This job') }
        }.freeze

        AGENT_CATEGORY_KEY = 'agent'

        # @param [User] user
        # @param [String] url
        # @param [Ai::AiResource] resource - one of the subtypes of AiResource
        # @param [Ai::FoundationalChatAgent] foundational_agent - the selected agent, already
        #   checked against what the user may select
        def initialize(user, url: nil, resource: nil, foundational_agent: nil)
          @user = user
          @resource = resource
          @page_url = url
          @foundational_agent = foundational_agent
        end

        def execute
          agent_questions = foundational_agent&.suggested_questions
          return agent_questions if agent_questions.present?

          return questions_from_resource if resource

          page_type ? page_type[:questions] : DEFAULT
        end

        # Questions grouped by category for the redesigned Duo Chat empty
        # state, ordered agent category first (when the selected agent defines
        # suggested questions), then contextual (when the current page yields
        # one), then the static topics. Question arrays are dup'ed because
        # Graphql::Authorize::FieldExtension calls `map!` on every list result,
        # which raises on a frozen constant.
        def categories
          [agent_category, contextual_category, *static_categories].compact
        end

        private

        attr_reader :user, :resource, :page_url, :foundational_agent

        # `contextual: false` even though this category comes first: the flag means
        # "about the current page", not "shown first". Agent questions are about
        # the selected agent, not the page.
        def agent_category
          questions = foundational_agent&.suggested_questions
          return if questions.blank?

          {
            key: AGENT_CATEGORY_KEY,
            title: foundational_agent.name,
            contextual: false,
            questions: questions.dup
          }
        end

        def static_categories
          STATIC_CATEGORIES.map do |category|
            category.merge(
              title: category[:title].call,
              contextual: false,
              questions: category[:questions].dup
            )
          end
        end

        def questions_from_resource
          return DEFAULT unless allowed_to_use_resource?

          resource.chat_questions
        end

        # A resolver asks one instance for both `execute` and `categories`,
        # and the entitlement check hits add-on and unit primitive lookups,
        # so run it once per request rather than once per code path.
        def allowed_to_use_resource?
          user.allowed_to_use?(
            resource.chat_unit_primitive,
            root_namespace: resource.root_namespace
          )
        end
        strong_memoize_attr :allowed_to_use_resource?

        # Resolving a route walks the whole route set, so both the flat
        # question list and the contextual category share one lookup.
        def route
          ::Gitlab::Llm::Utils::RouteHelper.new(page_url)
        end
        strong_memoize_attr :route

        def page_type
          return if page_url.blank?

          PAGE_TYPES[route.controller]
        end
        strong_memoize_attr :page_type

        def contextual_category
          return contextual_category_from_resource if resource
          return unless page_type

          {
            key: page_type[:key],
            title: page_type[:title].call,
            contextual: true,
            questions: page_type[:questions].dup
          }
        end

        # Ci::Pipeline defines no chat questions, so it would otherwise
        # surface as a category the user cannot open.
        def contextual_category_from_resource
          return if resource.chat_questions.empty?
          return unless allowed_to_use_resource?

          key = resource.current_page_type

          {
            key: key,
            title: resource.resource.try(:to_reference).presence || resource_title(key),
            contextual: true,
            questions: resource.chat_questions.dup
          }
        end

        def resource_title(key)
          RESOURCE_TITLES.fetch(key, DEFAULT_CONTEXTUAL_TITLE).call
        end
      end
    end
  end
end
