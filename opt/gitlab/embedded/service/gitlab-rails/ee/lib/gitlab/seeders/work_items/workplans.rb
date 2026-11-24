# frozen_string_literal: true

# rubocop:disable CodeReuse/ActiveRecord -- Seeder utility whose purpose is to create and look up records directly
module Gitlab
  module Seeders
    module WorkItems
      # Creates workflows and question notes directly, so no Duo Workflow Service is needed.
      class Workplans
        include ::Gitlab::Utils::StrongMemoize

        TITLE_PREFIX = '[Seed workplan]'
        FEATURE_FLAGS = %i[workplan decision_log].freeze

        SHORT_PLAN = <<~MARKDOWN
          ## Why

          Users want to export their data.

          ## How

          Add an export button.
        MARKDOWN

        FULL_PLAN = <<~MARKDOWN
          ## Why

          Project maintainers cannot see which pipelines are slow without opening each one.
          A per-project summary lets them spot regressions in a single view.

          ## How

          1. Add a `PipelineDurationSummary` finder that aggregates durations by week.
          1. Expose it through a new `project.pipelineDurationSummary` GraphQL field.
          1. Render a bar chart on the CI/CD analytics page behind the `pipeline_duration_summary` flag.

          ## What

          - [ ] Finder with specs for empty, single, and multi-week ranges
          - [ ] GraphQL field with N+1 spec
          - [ ] Vue chart component with Jest specs and empty state
          - [ ] Documentation update in `doc/ci/pipelines/pipeline_efficiency.md`

          ## Acceptance criteria

          - Durations match the pipeline list for the same range.
          - The chart loads in under one second for projects with 10,000 pipelines.
        MARKDOWN

        PARTIAL_PLAN = <<~MARKDOWN
          ## Why

          Project maintainers cannot see which pipelines are slow.

          ## How

          Aggregate pipeline durations and show them on the analytics page.

          ## What

          - [ ] Backend aggregation
          - [ ] Frontend chart
        MARKDOWN

        FEEDBACK = {
          low: <<~MARKDOWN,
            **Not ready for handoff.**

            - The problem statement does not say who is affected or why it matters.
            - There are no acceptance criteria.
            - The implementation steps do not name the components to change.
          MARKDOWN
          medium: <<~MARKDOWN,
            **Nearly ready.**

            - The plan names the components, but acceptance criteria are missing.
            - Performance expectations are not stated.
          MARKDOWN
          high: <<~MARKDOWN
            **Ready for handoff.**

            - Clear problem statement, concrete steps, and testable acceptance criteria.
            - Consider adding a rollback note for the feature flag.
          MARKDOWN
        }.freeze

        ANSWER_ID_CUSTOM = 'rejected'

        # Mirrors what the workplan flow posts: either a fenced payload or the older HTML-comment marker.
        QUESTIONS = {
          export_format: {
            context: "The description asks for an export but doesn't say which format users need.",
            payload: {
              type: 'closed',
              question: 'Which format should the first version of the export use?',
              options: [
                {
                  id: 'csv', label: 'CSV only', recommended: true,
                  description: 'Opens in any spreadsheet tool and is the smallest change.'
                },
                {
                  id: 'json', label: 'JSON only', recommended: false,
                  description: 'Keeps nested data, but is harder for non-technical users to read.'
                },
                {
                  id: 'csv_and_json', label: 'CSV and JSON', recommended: false,
                  description: 'Covers both audiences, but doubles the formats to test and maintain.'
                }
              ]
            }
          },
          export_scope: {
            context: 'The plan says "export their data" without naming which records are included.',
            payload: {
              type: 'closed',
              question: 'Which records should the export include?',
              multiple: true,
              options: [
                { id: 'issues', label: 'Issues', recommended: true },
                { id: 'merge_requests', label: 'Merge requests', recommended: true },
                { id: 'wiki', label: 'Wiki pages', recommended: false },
                {
                  id: 'ci_variables', label: 'CI/CD variable names', recommended: false,
                  description: 'Names only, never values.'
                }
              ]
            }
          },
          export_recipient: {
            context: "Large exports can't be generated inline. The plan doesn't say how users get the file.",
            payload: {
              type: 'open',
              question: 'How should users receive a large export once it is ready?'
            }
          },
          chart_range: {
            context: 'The acceptance criteria compare durations "for the same range", but set no default.',
            payload: {
              type: 'closed',
              question: 'What date range should the chart show by default?',
              options: [
                {
                  id: 'last_30_days', label: 'Last 30 days', recommended: true,
                  description: 'Matches the other CI/CD analytics charts.'
                },
                {
                  id: 'last_90_days', label: 'Last 90 days', recommended: false,
                  description: 'Shows longer trends, but queries more data.'
                },
                {
                  id: 'last_used', label: 'Last range the user picked', recommended: false,
                  description: 'Remembers the choice per user.'
                }
              ]
            }
          },
          child_pipelines: {
            context: 'Parent-child pipelines can double-count time if child durations are added to the parent.',
            payload: {
              type: 'closed',
              question: 'Should child pipeline durations count toward the summary?',
              options: [
                {
                  id: 'exclude_children', label: 'Exclude child pipelines', recommended: true,
                  description: "Only the parent's wall-clock duration counts."
                },
                {
                  id: 'include_children', label: 'Include child pipelines', recommended: false,
                  description: 'Each child pipeline is counted on its own.'
                }
              ]
            }
          },
          duration_metrics: {
            context: 'The plan says "aggregate durations" but not which statistics to show.',
            payload: {
              type: 'closed',
              question: 'Which duration metrics should the chart show?',
              multiple: true,
              options: [
                { id: 'median', label: 'Median', recommended: true },
                { id: 'p95', label: '95th percentile', recommended: true },
                { id: 'max', label: 'Maximum', recommended: false },
                { id: 'mean', label: 'Mean', recommended: false }
              ]
            }
          },
          failed_pipelines: {
            context: 'Failed and canceled pipelines often stop early, which would make averages look faster.',
            payload: {
              type: 'closed',
              question: 'How should failed and canceled pipelines be handled?',
              options: [
                {
                  id: 'exclude_failed', label: 'Exclude them', recommended: true,
                  description: 'Only successful pipelines count.'
                },
                { id: 'include_failed', label: 'Include them', recommended: false },
                { id: 'separate_series', label: 'Show them as a separate series', recommended: false }
              ]
            }
          },
          load_budget: {
            context: 'The one-second load target needs a reference project to measure against.',
            payload: {
              type: 'open',
              question: 'Which project, or what pipeline volume, should the load target be measured against?'
            }
          },
          chart_location: {
            context: 'Where should the new chart live?',
            marker: '<!-- duo:options ["CI/CD analytics page", "Pipelines list", "Overview"] duo:recommended 1 -->'
          }
        }.freeze

        # runs: generation runs oldest first; the last one is what the widget reports and owns the questions.
        # questions: [key, answer]. An answer is an option id, an array of ids, or { custom: 'text' }.
        SCENARIOS = [
          { key: '01', name: 'AI Planning enabled, no workplan yet', plan: nil },
          { key: '02', name: 'Workplan, not scored yet', plan: PARTIAL_PLAN, score: nil },
          { key: '03', name: 'Low (25)', plan: SHORT_PLAN, score: 25, feedback: :low },
          {
            key: '04', name: 'Medium (60)', plan: PARTIAL_PLAN, score: 60, feedback: :medium,
            runs: [:finished],
            questions: [[:chart_range, 'last_30_days'], [:child_pipelines, 'exclude_children']]
          },
          {
            key: '05', name: 'High (85)', plan: FULL_PLAN, score: 85, feedback: :high,
            runs: [:finished],
            questions: [[:chart_range, 'last_30_days'], [:failed_pipelines, 'exclude_failed']]
          },
          {
            key: '06', name: 'Open Duo questions (55)', plan: PARTIAL_PLAN, score: 55, feedback: :medium,
            runs: [:input_required],
            questions: [[:chart_range, 'last_30_days'], [:duration_metrics], [:load_budget], [:chart_location]]
          },
          {
            key: '07', name: 'All Duo questions answered (90)', plan: FULL_PLAN, score: 90, feedback: :high,
            runs: [:finished],
            questions: [
              [:chart_range, 'last_90_days'],
              [:child_pipelines, { custom: 'Include them, but as a separate series' }],
              [:duration_metrics, %w[median p95]],
              [:failed_pipelines, 'exclude_failed']
            ]
          },
          { key: '08', name: 'First generation run in progress', plan: nil, runs: [:running] },
          { key: '09', name: 'First generation run failed', plan: nil, runs: [:failed] },
          {
            key: '10', name: 'Re-run failed, earlier plan kept (60)', plan: PARTIAL_PLAN, score: 60,
            feedback: :medium, runs: [:finished, :failed]
          }
        ].freeze

        def initialize(project:, user:, reset: false)
          @project = project
          @user = user
          @reset = reset
        end

        # @return [Array<Hash>] one entry per scenario: the work item and whether it was created
        def seed!
          enable_feature_flags
          # By prefix rather than title, so items from renamed or renumbered scenarios go too.
          seeded_work_items.find_each { |work_item| destroy(work_item) } if reset

          SCENARIOS.map do |scenario|
            title = "#{TITLE_PREFIX} #{scenario[:key]} #{scenario[:name]}"
            existing = project.work_items.find_by(title: title)

            if existing
              { work_item: existing, scenario: scenario, created: false }
            else
              { work_item: seed_scenario(title, scenario), scenario: scenario, created: true }
            end
          end
        end

        private

        attr_reader :project, :user, :reset

        def seeded_work_items
          project.work_items.where('title LIKE ?', "#{Issue.sanitize_sql_like(TITLE_PREFIX)}%")
        end

        def enable_feature_flags
          FEATURE_FLAGS.each { |flag| Feature.enable(flag) }
        end

        def seed_scenario(title, scenario)
          work_item = create_work_item(title)

          begin
            # Always created: the widget stays hidden until ai_planning_enabled is set, even with no plan yet.
            create_agent_plan(work_item, scenario)

            workflow = Array(scenario[:runs]).map { |status| create_workflow(work_item, status) }.last
            questions = Array(scenario[:questions])

            if questions.any?
              author = decision_author(work_item)
              questions.each { |key, answer| create_question(work_item, workflow, key, answer, author) }
            end
          rescue StandardError
            # Otherwise the next run finds it by title and skips the half-built work item.
            destroy(work_item)
            raise
          end

          work_item
        end

        def create_work_item(title)
          result = ::WorkItems::CreateService.new(
            container: project,
            current_user: user,
            params: {
              title: title,
              description: 'Seeded by `gitlab:seed:workplans` to exercise the Workplan widget.',
              work_item_type_id: default_issue_type_id
            },
            perform_spam_check: false
          ).execute

          raise "Failed to create #{title}: #{result.message}" if result.error?

          result[:work_item]
        end

        def default_issue_type_id
          ::WorkItems::TypesFramework::Provider.new(project).default_issue_type.id
        end
        strong_memoize_attr :default_issue_type_id

        def create_agent_plan(work_item, scenario)
          ::WorkItems::AgentPlan.create!(
            work_item: work_item,
            content: scenario[:plan],
            readiness_score: scenario[:score],
            readiness_score_feedback: FEEDBACK[scenario[:feedback]],
            ai_planning_enabled: true
          )
        end

        def create_workflow(work_item, status)
          ::Ai::DuoWorkflows::Workflow.create!(
            user: user,
            project: project,
            work_item: work_item,
            goal: ::Ai::Catalog::GoalTemplates::Workplan.resolve(resource: work_item),
            workflow_definition: ::Ai::Catalog::FoundationalFlow.workplan_v1.reference,
            environment: :web,
            service_account: service_account,
            status: ::Ai::DuoWorkflows::Workflow.state_machines[:status].states[status].value
          )
        end

        # Mirrors EE::Notes::CreateService for a flow-authored note: link it, then record its decision.
        def create_question(work_item, workflow, key, answer, author)
          question = QUESTIONS.fetch(key)
          note = DiscussionNote.create!(
            noteable: work_item, project: project, author: service_account || user, note: question_body(question)
          )

          errors = ::Ai::DuoWorkflows::WorkflowNote.ensure_link(workflow: workflow, artifact: note, link_type: :created)
          raise "Failed to link question note: #{errors.full_messages.to_sentence}" if errors.any?

          response = ::WorkItems::Decisions::CreateFromDuoQuestionService.new(
            note: note, workflow: workflow, current_user: author
          ).execute
          raise "Failed to create decision: #{response.message}" if response&.error?

          # nil when no decision was recorded, for example without a service account.
          decision = response&.payload&.dig(:decision)
          answer_question(work_item, note, question, answer, decision) if answer
        end

        def question_body(question)
          payload = question[:marker] || "```json:duo-question\n#{::Gitlab::Json.generate(question[:payload])}\n```"

          "@#{user.username} #{question[:context]}\n\n#{payload}\n"
        end

        # Mirrors what the question card does on answer: reply, resolve the thread, then resolve the decision.
        def answer_question(work_item, note, question, answer, decision)
          reply = DiscussionNote.create!(
            noteable: work_item, project: project, author: user, note: answer_body(question, answer),
            discussion_id: note.discussion_id
          )
          # Re-fetched because `discussion` is memoized: a copy without the reply would leave the reply
          # unresolved, and WorkplanQuestions counts a thread as answered only when every note is resolved.
          Note.find(note.id).discussion.resolve!(user)

          return unless decision

          params = if answer.is_a?(Hash)
                     { selected_option_content: answer[:custom] }
                   else
                     labels = option_labels(question, answer)
                     { selected_option_ids: decision.options.select { |o| labels.include?(o.content) }.map(&:id) }
                   end

          response = ::WorkItems::Decisions::ResolveService.new(
            decision: decision, current_user: user, params: params.merge(resolving_note: reply)
          ).execute
          raise "Failed to resolve decision: #{response.message}" if response.error?
        end

        # Same formats as buildDuoAnswer and buildDuoAnswers in duo_question.js.
        def answer_body(question, answer)
          return "#{answer[:custom]}\n\n<!-- duo-answer: #{ANSWER_ID_CUSTOM} -->" if answer.is_a?(Hash)

          labels = option_labels(question, answer)
          return "#{labels.first}\n\n<!-- duo-answer: #{answer} -->" unless answer.is_a?(Array)

          "#{labels.map { |label| "- #{label}" }.join("\n")}\n\n<!-- duo-answer: #{answer.join(',')} -->"
        end

        def option_labels(question, answer)
          ids = Array(answer)

          question[:payload][:options].select { |option| ids.include?(option[:id]) }.pluck(:label)
        end

        # The flow's service account, as CreateAndStartWorkflowService resolves it. Without one,
        # questions are posted by the seeding user and get no decision.
        def service_account
          item = ::Ai::Catalog::FoundationalFlow.workplan_v1.catalog_item
          return unless item

          result = ::Ai::Catalog::ItemConsumers::ResolveServiceAccountService
            .new(container: project, item: item).execute
          account = result.payload[:service_account] if result.success?

          # An account left over from a flow that was turned off. Named as in ItemConsumers::CreateService.
          account ||= ::User.find_by_username("duo-#{item.name}-#{project.root_ancestor.name}".parameterize)

          account if account&.service_account?
        end
        strong_memoize_attr :service_account

        # A leftover service account may have lost access to the project.
        def decision_author(work_item)
          Ability.allowed?(service_account, :update_work_item, work_item) ? service_account : user
        end

        def destroy(work_item)
          ::Ai::DuoWorkflows::Workflow.for_issue(work_item.id).find_each(&:destroy!)
          work_item.destroy!
        end
      end
    end
  end
end
# rubocop:enable CodeReuse/ActiveRecord
